// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

extern crate alloc;

use crate::acpi::tables::{load_acpi_cpu_info, ACPICPUInfo, ACPITable};
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::efer::EFERFlags;
use crate::error::SvsmError;
use crate::mm::{GuestPtr, PerCPUPageMappingGuard, PAGE_SIZE};
use crate::platform::{PageStateChangeOp, PageValidateOp, SevFWMetaData, SVSM_PLATFORM};
use crate::types::PageSize;
use crate::utils::MemoryRegion;
use alloc::vec::Vec;
use cpuarch::vmsa::VMSA;

use bootlib::igvm_params::{IgvmGuestContext, IgvmParamBlock, IgvmParamPage};
use bootlib::kernel_launch::LOWMEM_END;
use core::mem::size_of;
use core::slice;
use igvm_defs::{IgvmEnvironmentInfo, MemoryMapEntryType, IGVM_VHS_MEMORY_MAP_ENTRY};

const IGVM_MEMORY_ENTRIES_PER_PAGE: usize = PAGE_SIZE / size_of::<IGVM_VHS_MEMORY_MAP_ENTRY>();

#[derive(Clone, Debug)]
#[repr(C, align(64))]
pub struct IgvmMemoryMap {
    memory_map: [IGVM_VHS_MEMORY_MAP_ENTRY; IGVM_MEMORY_ENTRIES_PER_PAGE],
}

#[derive(Clone, Debug)]
pub struct IgvmParams<'a> {
    igvm_param_block: &'a IgvmParamBlock,
    igvm_param_page: &'a IgvmParamPage,
    igvm_memory_map: &'a IgvmMemoryMap,
    igvm_madt: Option<&'a [u8]>,
    igvm_guest_context: Option<&'a IgvmGuestContext>,
}

impl IgvmParams<'_> {
    pub fn new(addr: VirtAddr) -> Result<Self, SvsmError> {
        let param_block = Self::try_aligned_ref::<IgvmParamBlock>(addr)?;
        let param_page_address = addr + param_block.param_page_offset as usize;
        let param_page = Self::try_aligned_ref::<IgvmParamPage>(param_page_address)?;
        let memory_map_address = addr + param_block.memory_map_offset as usize;
        let memory_map = Self::try_aligned_ref::<IgvmMemoryMap>(memory_map_address)?;
        let madt_address = addr + param_block.madt_offset as usize;
        let madt = if param_block.madt_size != 0 {
            // SAFETY: the parameter block correctly describes the bounds of the
            // MADT.
            unsafe {
                Some(slice::from_raw_parts(
                    madt_address.as_ptr::<u8>(),
                    param_block.madt_size as usize,
                ))
            }
        } else {
            None
        };
        let guest_context = if param_block.guest_context_offset != 0 {
            let offset = usize::try_from(param_block.guest_context_offset).unwrap();
            Some(Self::try_aligned_ref::<IgvmGuestContext>(addr + offset)?)
        } else {
            None
        };

        Ok(Self {
            igvm_param_block: param_block,
            igvm_param_page: param_page,
            igvm_memory_map: memory_map,
            igvm_madt: madt,
            igvm_guest_context: guest_context,
        })
    }

    fn try_aligned_ref<'a, T>(addr: VirtAddr) -> Result<&'a T, SvsmError> {
        // SAFETY: we trust the caller to provide an address pointing to valid
        // memory which is not mutably aliased.
        unsafe { addr.aligned_ref::<T>().ok_or(SvsmError::Firmware) }
    }

    pub fn size(&self) -> usize {
        // Calculate the total size of the parameter area.  The
        // parameter area always begins at the kernel base
        // address.
        self.igvm_param_block.param_area_size.try_into().unwrap()
    }

    pub fn find_kernel_region(&self) -> Result<MemoryRegion<PhysAddr>, SvsmError> {
        let kernel_base = PhysAddr::from(self.igvm_param_block.kernel_base);
        let mut kernel_size = self.igvm_param_block.kernel_min_size;

        // Check the untrusted hypervisor-provided memory map to see if the size of the kernel
        // should be adjusted. The base location and mimimum and maximum size specified by the
        // measured igvm_param_block are still respected to ensure a malicious memory map cannot
        // cause the SVSM kernel to overlap anything important or be so small it causes weird
        // failures. But if the hypervisor gives a memory map entry of type HIDDEN that starts at
        // kernel_start, use the size of that entry as a guide. This allows the hypervisor to
        // adjust the size of the SVSM kernel to what it expects will be needed based on the
        // machine shape.
        if let Some(memory_map_region) = self.igvm_memory_map.memory_map.iter().find(|region| {
            region.entry_type == MemoryMapEntryType::HIDDEN
                && region.starting_gpa_page_number.try_into() == Ok(kernel_base.pfn())
        }) {
            let region_size_bytes = memory_map_region
                .number_of_pages
                .try_into()
                .unwrap_or(u32::MAX)
                .saturating_mul(PAGE_SIZE as u32);
            kernel_size = region_size_bytes.clamp(
                self.igvm_param_block.kernel_min_size,
                self.igvm_param_block.kernel_max_size,
            );
        }
        Ok(MemoryRegion::<PhysAddr>::new(
            kernel_base,
            kernel_size.try_into().unwrap(),
        ))
    }

    pub fn reserved_kernel_area_size(&self) -> usize {
        self.igvm_param_block
            .kernel_reserved_size
            .try_into()
            .unwrap()
    }

    pub fn page_state_change_required(&self) -> bool {
        let environment_info = IgvmEnvironmentInfo::from(self.igvm_param_page.environment_info);
        environment_info.memory_is_shared()
    }

    pub fn get_memory_regions(&self) -> Result<Vec<MemoryRegion<PhysAddr>>, SvsmError> {
        // Count the number of memory entries present.  They must be
        // non-overlapping and strictly increasing.
        let mut number_of_entries = 0;
        let mut next_page_number = 0;
        for entry in self.igvm_memory_map.memory_map.iter() {
            if entry.number_of_pages == 0 {
                break;
            }
            if entry.starting_gpa_page_number < next_page_number {
                return Err(SvsmError::Firmware);
            }
            let next_supplied_page_number = entry.starting_gpa_page_number + entry.number_of_pages;
            if next_supplied_page_number < next_page_number {
                return Err(SvsmError::Firmware);
            }
            next_page_number = next_supplied_page_number;
            number_of_entries += 1;
        }

        // Now loop over the supplied entires and add a region for each
        // known type.
        let mut regions: Vec<MemoryRegion<PhysAddr>> = Vec::new();
        for entry in self
            .igvm_memory_map
            .memory_map
            .iter()
            .take(number_of_entries)
        {
            if entry.entry_type == MemoryMapEntryType::MEMORY {
                let starting_page: usize = entry.starting_gpa_page_number.try_into().unwrap();
                let number_of_pages: usize = entry.number_of_pages.try_into().unwrap();
                regions.push(MemoryRegion::new(
                    PhysAddr::new(starting_page * PAGE_SIZE),
                    number_of_pages * PAGE_SIZE,
                ));
            }
        }

        Ok(regions)
    }

    pub fn write_guest_memory_map(&self, map: &[MemoryRegion<PhysAddr>]) -> Result<(), SvsmError> {
        // If the parameters do not include a guest memory map area, then no
        // work is required.
        let fw_info = &self.igvm_param_block.firmware;
        if fw_info.memory_map_page_count == 0 {
            return Ok(());
        }

        // Map the guest memory map area into the address space.
        let mem_map_gpa = PhysAddr::from(fw_info.memory_map_page as u64 * PAGE_SIZE as u64);
        let mem_map_region = MemoryRegion::<PhysAddr>::new(
            mem_map_gpa,
            fw_info.memory_map_page_count as usize * PAGE_SIZE,
        );
        log::info!(
            "Filling guest IGVM memory map at {:#018x} size {:#018x}",
            mem_map_region.start(),
            mem_map_region.len(),
        );

        let mem_map_mapping =
            PerCPUPageMappingGuard::create(mem_map_region.start(), mem_map_region.end(), 0)?;
        let mem_map_va = mem_map_mapping.virt_addr();

        // The guest expects the pages in the memory map to be treated like
        // host-provided IGVM parameters, which requires the pages to be
        // validated.  Since the memory was not declared as part of the guest
        // firmware image, the pages must be validated here.
        if self.page_state_change_required() {
            SVSM_PLATFORM.page_state_change(
                mem_map_region,
                PageSize::Regular,
                PageStateChangeOp::Private,
            )?;
        }

        let mem_map_va_region = MemoryRegion::<VirtAddr>::new(mem_map_va, mem_map_region.len());
        SVSM_PLATFORM.validate_virtual_page_range(mem_map_va_region, PageValidateOp::Validate)?;

        // Calculate the maximum number of entries that can be inserted.
        let max_entries = fw_info.memory_map_page_count as usize * PAGE_SIZE
            / size_of::<IGVM_VHS_MEMORY_MAP_ENTRY>();

        // Generate a guest pointer range to hold the memory map.
        let mem_map = GuestPtr::new(mem_map_va);

        for (i, entry) in map.iter().enumerate() {
            // Return an error if an overflow occurs.
            if i >= max_entries {
                return Err(SvsmError::Firmware);
            }

            // SAFETY: mem_map_va points to newly mapped memory, whose physical
            // address is defined in the IGVM config.
            unsafe {
                mem_map
                    .offset(i as isize)
                    .write(IGVM_VHS_MEMORY_MAP_ENTRY {
                        starting_gpa_page_number: u64::from(entry.start()) / PAGE_SIZE as u64,
                        number_of_pages: entry.len() as u64 / PAGE_SIZE as u64,
                        entry_type: MemoryMapEntryType::default(),
                        flags: 0,
                        reserved: 0,
                    })?;
            }
        }

        // Write a zero page count into the last entry to terminate the list.
        let index = map.len();
        if index < max_entries {
            // SAFETY: mem_map_va points to newly mapped memory, whose physical
            // address is defined in the IGVM config.
            unsafe {
                mem_map
                    .offset(index as isize)
                    .write(IGVM_VHS_MEMORY_MAP_ENTRY {
                        starting_gpa_page_number: 0,
                        number_of_pages: 0,
                        entry_type: MemoryMapEntryType::default(),
                        flags: 0,
                        reserved: 0,
                    })?;
            }
        }

        Ok(())
    }

    pub fn load_cpu_info(&self) -> Result<Option<Vec<ACPICPUInfo>>, SvsmError> {
        match self.igvm_madt {
            Some(madt_data) => {
                let madt = ACPITable::new(madt_data)?;
                Ok(Some(load_acpi_cpu_info(&madt)?))
            }
            None => Ok(None),
        }
    }

    pub fn should_launch_fw(&self) -> bool {
        self.igvm_param_block.firmware.size != 0
    }

    pub fn debug_serial_port(&self) -> u16 {
        self.igvm_param_block.debug_serial_port
    }

    pub fn get_fw_metadata(&self) -> Option<SevFWMetaData> {
        if !self.should_launch_fw() {
            return None;
        }

        let mut fw_meta = SevFWMetaData::new();

        if self.igvm_param_block.firmware.caa_page != 0 {
            fw_meta.caa_page = Some(PhysAddr::new(
                self.igvm_param_block.firmware.caa_page.try_into().unwrap(),
            ));
        }

        if self.igvm_param_block.firmware.secrets_page != 0 {
            fw_meta.secrets_page = Some(PhysAddr::new(
                self.igvm_param_block
                    .firmware
                    .secrets_page
                    .try_into()
                    .unwrap(),
            ));
        }

        if self.igvm_param_block.firmware.cpuid_page != 0 {
            fw_meta.cpuid_page = Some(PhysAddr::new(
                self.igvm_param_block
                    .firmware
                    .cpuid_page
                    .try_into()
                    .unwrap(),
            ));
        }

        let preval_count = self.igvm_param_block.firmware.prevalidated_count as usize;
        for preval in self
            .igvm_param_block
            .firmware
            .prevalidated
            .iter()
            .take(preval_count)
        {
            let base = PhysAddr::from(preval.base as usize);
            fw_meta.add_valid_mem(base, preval.size as usize);
        }

        Some(fw_meta)
    }

    pub fn get_fw_regions(&self) -> Vec<MemoryRegion<PhysAddr>> {
        assert!(self.should_launch_fw());

        let mut regions = Vec::new();

        if self.igvm_param_block.firmware.in_low_memory != 0 {
            // Add the lowmem region to the firmware region list so
            // permissions can be granted to the guest VMPL for that range.
            regions.push(MemoryRegion::from_addresses(
                PhysAddr::from(0u64),
                PhysAddr::from(u64::from(LOWMEM_END)),
            ));
        }

        regions.push(MemoryRegion::new(
            PhysAddr::new(self.igvm_param_block.firmware.start as usize),
            self.igvm_param_block.firmware.size as usize,
        ));

        regions
    }

    pub fn fw_in_low_memory(&self) -> bool {
        self.igvm_param_block.firmware.in_low_memory != 0
    }

    pub fn initialize_guest_vmsa(&self, vmsa: &mut VMSA) -> Result<(), SvsmError> {
        let Some(guest_context) = self.igvm_guest_context else {
            return Ok(());
        };

        // Copy the specified registers into the VMSA.
        vmsa.cr0 = guest_context.cr0;
        vmsa.cr3 = guest_context.cr3;
        vmsa.cr4 = guest_context.cr4;
        vmsa.efer = guest_context.efer;
        vmsa.rip = guest_context.rip;
        vmsa.rax = guest_context.rax;
        vmsa.rcx = guest_context.rcx;
        vmsa.rdx = guest_context.rdx;
        vmsa.rbx = guest_context.rbx;
        vmsa.rsp = guest_context.rsp;
        vmsa.rbp = guest_context.rbp;
        vmsa.rsi = guest_context.rsi;
        vmsa.rdi = guest_context.rdi;
        vmsa.r8 = guest_context.r8;
        vmsa.r9 = guest_context.r9;
        vmsa.r10 = guest_context.r10;
        vmsa.r11 = guest_context.r11;
        vmsa.r12 = guest_context.r12;
        vmsa.r13 = guest_context.r13;
        vmsa.r14 = guest_context.r14;
        vmsa.r15 = guest_context.r15;
        vmsa.gdt.base = guest_context.gdt_base;
        vmsa.gdt.limit = guest_context.gdt_limit;

        // If a non-zero code selector is specified, then set the code
        // segment attributes based on EFER.LMA.
        if guest_context.code_selector != 0 {
            vmsa.cs.selector = guest_context.code_selector;
            let efer_lma = EFERFlags::LMA;
            if (vmsa.efer & efer_lma.bits()) != 0 {
                vmsa.cs.flags = 0xA9B;
            } else {
                vmsa.cs.flags = 0xC9B;
                vmsa.cs.limit = 0xFFFFFFFF;
            }
        }

        let efer_svme = EFERFlags::SVME;
        vmsa.efer &= !efer_svme.bits();

        // If a non-zero data selector is specified, then modify the data
        // segment attributes to be compatible with protected mode.
        if guest_context.data_selector != 0 {
            vmsa.ds.selector = guest_context.data_selector;
            vmsa.ds.flags = 0xA93;
            vmsa.ds.limit = 0xFFFFFFFF;
            vmsa.ss = vmsa.ds;
            vmsa.es = vmsa.ds;
            vmsa.fs = vmsa.ds;
            vmsa.gs = vmsa.ds;
        }

        // Configure vTOM if requested.
        if self.igvm_param_block.vtom != 0 {
            vmsa.vtom = self.igvm_param_block.vtom;
            vmsa.sev_features |= 2; // VTOM feature
        }

        Ok(())
    }

    pub fn get_vtom(&self) -> u64 {
        self.igvm_param_block.vtom
    }

    pub fn use_alternate_injection(&self) -> bool {
        self.igvm_param_block.use_alternate_injection != 0
    }

    pub fn is_qemu(&self) -> bool {
        self.igvm_param_block.is_qemu != 0
    }
}
