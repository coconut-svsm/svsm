// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::address::PhysAddr;
use crate::config::SvsmConfig;
use crate::cpu::cpuid::copy_cpuid_table_to;
use crate::cpu::percpu::{current_ghcb, this_cpu, this_cpu_shared};
use crate::error::SvsmError;
use crate::mm::PerCPUPageMappingGuard;
use crate::platform::PageStateChangeOp;
use crate::sev::{pvalidate, rmp_adjust, secrets_page, PvalidateOp, RMPFlags};
use crate::types::{PageSize, GUEST_VMPL, PAGE_SIZE};
use crate::utils::{zero_mem_region, MemoryRegion};
use alloc::vec::Vec;
use zerocopy::{FromBytes, Immutable, KnownLayout};

#[derive(Clone, Debug, Default)]
pub struct SevFWMetaData {
    pub cpuid_page: Option<PhysAddr>,
    pub secrets_page: Option<PhysAddr>,
    pub caa_page: Option<PhysAddr>,
    pub valid_mem: Vec<MemoryRegion<PhysAddr>>,
}

impl SevFWMetaData {
    pub const fn new() -> Self {
        Self {
            cpuid_page: None,
            secrets_page: None,
            caa_page: None,
            valid_mem: Vec::new(),
        }
    }

    pub fn add_valid_mem(&mut self, base: PhysAddr, len: usize) {
        self.valid_mem.push(MemoryRegion::new(base, len));
    }
}

#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct SevMetaDataHeader {
    signature: [u8; 4],
    len: u32,
    version: u32,
    num_desc: u32,
}

#[derive(Clone, Copy, Debug, FromBytes, KnownLayout, Immutable)]
#[repr(C, packed)]
struct SevMetaDataDesc {
    base: u32,
    len: u32,
    t: u32,
}

fn validate_fw_mem_region(
    config: &SvsmConfig<'_>,
    region: MemoryRegion<PhysAddr>,
) -> Result<(), SvsmError> {
    let pstart = region.start();
    let pend = region.end();

    log::info!("Validating {:#018x}-{:#018x}", pstart, pend);

    if config.page_state_change_required() {
        current_ghcb()
            .page_state_change(region, PageSize::Regular, PageStateChangeOp::Private)
            .expect("GHCB PSC call failed to validate firmware memory");
    }

    for paddr in region.iter_pages(PageSize::Regular) {
        let guard = PerCPUPageMappingGuard::create_4k(paddr)?;
        let vaddr = guard.virt_addr();

        // SAFETY: the virtual address mapping is known to point to the guest
        // physical address range supplied by the caller.
        unsafe {
            pvalidate(vaddr, PageSize::Regular, PvalidateOp::Valid)?;

            // Make page accessible to guest VMPL
            rmp_adjust(
                vaddr,
                RMPFlags::GUEST_VMPL | RMPFlags::RWX,
                PageSize::Regular,
            )?;

            zero_mem_region(vaddr, vaddr + PAGE_SIZE);
        }
    }

    Ok(())
}

fn validate_fw_memory_vec(
    config: &SvsmConfig<'_>,
    regions: Vec<MemoryRegion<PhysAddr>>,
) -> Result<(), SvsmError> {
    if regions.is_empty() {
        return Ok(());
    }

    let mut next_vec = Vec::new();
    let mut region = regions[0];

    for next in regions.into_iter().skip(1) {
        if region.contiguous(&next) {
            region = region.merge(&next);
        } else {
            next_vec.push(next);
        }
    }

    validate_fw_mem_region(config, region)?;
    validate_fw_memory_vec(config, next_vec)
}

pub fn validate_fw_memory(
    config: &SvsmConfig<'_>,
    fw_meta: &SevFWMetaData,
    kernel_region: &MemoryRegion<PhysAddr>,
) -> Result<(), SvsmError> {
    // Initalize vector with regions from the FW
    let mut regions = fw_meta.valid_mem.clone();

    // Add region for CPUID page if present
    if let Some(cpuid_paddr) = fw_meta.cpuid_page {
        regions.push(MemoryRegion::new(cpuid_paddr, PAGE_SIZE));
    }

    // Add region for Secrets page if present
    if let Some(secrets_paddr) = fw_meta.secrets_page {
        regions.push(MemoryRegion::new(secrets_paddr, PAGE_SIZE));
    }

    // Add region for CAA page if present
    if let Some(caa_paddr) = fw_meta.caa_page {
        regions.push(MemoryRegion::new(caa_paddr, PAGE_SIZE));
    }

    // Sort regions by base address
    regions.sort_unstable_by_key(|a| a.start());

    for region in regions.iter() {
        if region.overlap(kernel_region) {
            log::error!("FwMeta region ovelaps with kernel");
            return Err(SvsmError::Firmware);
        }
    }

    validate_fw_memory_vec(config, regions)
}

pub fn print_fw_meta(fw_meta: &SevFWMetaData) {
    log::info!("FW Meta Data");

    match fw_meta.cpuid_page {
        Some(addr) => log::info!("  CPUID Page   : {:#010x}", addr),
        None => log::info!("  CPUID Page   : None"),
    };

    match fw_meta.secrets_page {
        Some(addr) => log::info!("  Secrets Page : {:#010x}", addr),
        None => log::info!("  Secrets Page : None"),
    };

    match fw_meta.caa_page {
        Some(addr) => log::info!("  CAA Page     : {:#010x}", addr),
        None => log::info!("  CAA Page     : None"),
    };

    for region in &fw_meta.valid_mem {
        log::info!("  Pre-Validated Region {region:#018x}");
    }
}

fn copy_cpuid_table_to_fw(fw_addr: PhysAddr) -> Result<(), SvsmError> {
    let guard = PerCPUPageMappingGuard::create_4k(fw_addr)?;

    // SAFETY: this is called from CPU 0, so the underlying physical address
    // is not being aliased. We are mapping a full page, which is 4K-aligned,
    // and is enough for SnpCpuidTable.
    unsafe {
        copy_cpuid_table_to(guard.virt_addr());
    }

    Ok(())
}

fn copy_secrets_page_to_fw(
    fw_addr: PhysAddr,
    caa_addr: PhysAddr,
    kernel_region: &MemoryRegion<PhysAddr>,
) -> Result<(), SvsmError> {
    let guard = PerCPUPageMappingGuard::create_4k(fw_addr)?;
    let start = guard.virt_addr();

    // Zero target
    // SAFETY: we trust PerCPUPageMappingGuard::create_4k() to return a
    // valid pointer to a correctly mapped region of size PAGE_SIZE.
    unsafe {
        zero_mem_region(start, start + PAGE_SIZE);
    }

    // Copy secrets page
    let mut fw_secrets_page = secrets_page().copy_for_vmpl(GUEST_VMPL);

    fw_secrets_page.set_svsm_data(
        kernel_region.start().into(),
        kernel_region.len().try_into().unwrap(),
        u64::from(caa_addr),
    );

    // SAFETY: start points to a new allocated and zeroed page.
    unsafe {
        fw_secrets_page.copy_to(start);
    }

    Ok(())
}

fn zero_caa_page(fw_addr: PhysAddr) -> Result<(), SvsmError> {
    let guard = PerCPUPageMappingGuard::create_4k(fw_addr)?;
    let vaddr = guard.virt_addr();

    // SAFETY: we trust PerCPUPageMappingGuard::create_4k() to return a
    // valid pointer to a correctly mapped region of size PAGE_SIZE.
    unsafe {
        zero_mem_region(vaddr, vaddr + PAGE_SIZE);
    }

    Ok(())
}

pub fn copy_tables_to_fw(
    fw_meta: &SevFWMetaData,
    kernel_region: &MemoryRegion<PhysAddr>,
) -> Result<(), SvsmError> {
    if let Some(addr) = fw_meta.cpuid_page {
        copy_cpuid_table_to_fw(addr)?;
    }

    let secrets_page = fw_meta.secrets_page.ok_or(SvsmError::MissingSecrets)?;
    let caa_page = fw_meta.caa_page.ok_or(SvsmError::MissingCAA)?;

    copy_secrets_page_to_fw(secrets_page, caa_page, kernel_region)?;

    zero_caa_page(caa_page)?;

    Ok(())
}

pub fn validate_fw(
    config: &SvsmConfig<'_>,
    kernel_region: &MemoryRegion<PhysAddr>,
) -> Result<(), SvsmError> {
    let flash_regions = config.get_fw_regions(kernel_region);

    for (i, region) in flash_regions.into_iter().enumerate() {
        log::info!(
            "Flash region {} at {:#018x} size {:018x}",
            i,
            region.start(),
            region.len(),
        );

        for paddr in region.iter_pages(PageSize::Regular) {
            let guard = PerCPUPageMappingGuard::create_4k(paddr)?;
            let vaddr = guard.virt_addr();
            // SAFETY: the address is known to be a guest page.
            if let Err(e) = unsafe {
                rmp_adjust(
                    vaddr,
                    RMPFlags::GUEST_VMPL | RMPFlags::RWX,
                    PageSize::Regular,
                )
            } {
                log::info!("rmpadjust failed for addr {:#018x}", vaddr);
                return Err(e);
            }
        }
    }

    Ok(())
}

pub fn prepare_fw_launch(fw_meta: &SevFWMetaData) -> Result<(), SvsmError> {
    if let Some(caa) = fw_meta.caa_page {
        this_cpu_shared().update_guest_caa(caa);
    }

    this_cpu().alloc_guest_vmsa()?;
    this_cpu().update_guest_mappings()?;

    Ok(())
}

pub fn launch_fw(config: &SvsmConfig<'_>) -> Result<(), SvsmError> {
    let cpu = this_cpu();
    let mut vmsa_ref = cpu.guest_vmsa_ref();
    let vmsa_pa = vmsa_ref.vmsa_phys().unwrap();
    let vmsa = vmsa_ref.vmsa();

    config.initialize_guest_vmsa(vmsa)?;

    log::info!("VMSA PA: {:#x}", vmsa_pa);

    let sev_features = vmsa.sev_features;

    log::info!("Launching Firmware");
    current_ghcb().register_guest_vmsa(vmsa_pa, 0, GUEST_VMPL as u64, sev_features)?;

    Ok(())
}
