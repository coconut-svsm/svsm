// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

extern crate alloc;

use crate::acpi::tables::ACPICPUInfo;
use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::igvm_params::IgvmParams;
use crate::platform::SevFWMetaData;
use crate::utils::MemoryRegion;
use alloc::vec::Vec;
use cpuarch::vmsa::VMSA;

fn check_ovmf_regions(
    ovmf_regions: &[MemoryRegion<PhysAddr>],
    kernel_region: &MemoryRegion<PhysAddr>,
) {
    let flash_range = {
        let one_gib = 1024 * 1024 * 1024usize;
        let start = PhysAddr::from(3 * one_gib);
        MemoryRegion::new(start, one_gib)
    };
    let mut one_region_ends_at_4gib = false;

    // Sanity-check OVMF regions.
    for (i, region) in ovmf_regions.iter().enumerate() {
        // Make sure that regions don't overlap.
        for other in ovmf_regions[..i].iter() {
            if other.overlap(region) {
                panic!("OVMF regions overlap: {region:#018x} | {other:#018x}");
            }
        }
        if flash_range.overlap(region) {
            assert!(
                flash_range.contains_region(region),
                "Flash region {region:#018x} in unexpected location"
            );
            // Make sure that one region ends at 4GiB.
            if region.end() == flash_range.end() {
                one_region_ends_at_4gib = true;
            }
        }
        // Make sure that no regions overlap with the kernel.
        if kernel_region.overlap(region) {
            panic!("OVMF region {region:#018x} overlaps with kernel {kernel_region:#018x}");
        }
    }
    assert!(one_region_ends_at_4gib, "No OVMF region ends at 4GiB");
}

#[derive(Debug)]
pub struct SvsmConfig<'a> {
    igvm_params: &'a IgvmParams<'a>,
}

impl<'a> SvsmConfig<'a> {
    pub fn new(igvm_params: &'a IgvmParams<'a>) -> SvsmConfig<'a> {
        Self { igvm_params }
    }

    pub fn get_igvm_params(&self) -> &IgvmParams<'_> {
        self.igvm_params
    }

    pub fn find_kernel_region(&self) -> Result<MemoryRegion<PhysAddr>, SvsmError> {
        self.igvm_params.find_kernel_region()
    }
    pub fn page_state_change_required(&self) -> bool {
        self.igvm_params.page_state_change_required()
    }
    pub fn get_memory_regions(&self) -> Result<Vec<MemoryRegion<PhysAddr>>, SvsmError> {
        self.igvm_params.get_memory_regions()
    }
    pub fn write_guest_memory_map(&self, map: &[MemoryRegion<PhysAddr>]) -> Result<(), SvsmError> {
        self.igvm_params.write_guest_memory_map(map)
    }
    pub fn reserved_kernel_area_size(&self) -> usize {
        self.igvm_params.reserved_kernel_area_size()
    }
    pub fn load_cpu_info(&self) -> Result<Vec<ACPICPUInfo>, SvsmError> {
        // Attempt to collect the CPU information from the IGVM parameters.
        // This will fail if the MADT was not supplied via IGVM parameter
        // injection.
        self.igvm_params.load_cpu_info()
    }

    pub fn should_launch_fw(&self) -> bool {
        self.igvm_params.should_launch_fw()
    }

    pub fn debug_serial_port(&self) -> u16 {
        self.igvm_params.debug_serial_port()
    }

    pub fn get_fw_metadata(&self) -> Option<SevFWMetaData> {
        self.igvm_params.get_fw_metadata()
    }

    pub fn get_fw_regions(
        &self,
        kernel_region: &MemoryRegion<PhysAddr>,
    ) -> Vec<MemoryRegion<PhysAddr>> {
        let fw_regions = self.igvm_params.get_fw_regions();
        if !self.igvm_params.fw_in_low_memory() {
            check_ovmf_regions(&fw_regions, kernel_region);
        }
        fw_regions
    }

    pub fn fw_in_low_memory(&self) -> bool {
        self.igvm_params.fw_in_low_memory()
    }

    pub fn initialize_guest_vmsa(&self, vmsa: &mut VMSA) -> Result<(), SvsmError> {
        self.igvm_params.initialize_guest_vmsa(vmsa)
    }

    pub fn use_alternate_injection(&self) -> bool {
        self.igvm_params.use_alternate_injection()
    }

    pub fn suppress_svsm_interrupts_on_snp(&self) -> bool {
        self.igvm_params.suppress_svsm_interrupts_on_snp()
    }

    pub fn has_qemu_testdev(&self) -> bool {
        self.igvm_params.has_qemu_testdev()
    }

    pub fn has_test_iorequests(&self) -> bool {
        self.igvm_params.has_test_iorequests()
    }
}
