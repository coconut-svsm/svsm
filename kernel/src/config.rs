// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

extern crate alloc;

use crate::acpi::tables::{load_fw_cpu_info, ACPICPUInfo};
use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::fw_cfg::FwCfg;
use crate::igvm_params::IgvmParams;
use crate::platform::{SevFWMetaData, SvsmPlatform};
use crate::utils::MemoryRegion;
use alloc::vec::Vec;
use cpuarch::vmsa::VMSA;

fn check_ovmf_regions(
    flash_regions: &[MemoryRegion<PhysAddr>],
    kernel_region: &MemoryRegion<PhysAddr>,
) {
    let flash_range = {
        let one_gib = 1024 * 1024 * 1024usize;
        let start = PhysAddr::from(3 * one_gib);
        MemoryRegion::new(start, one_gib)
    };

    // Sanity-check flash regions.
    for region in flash_regions.iter() {
        // Make sure that the regions are between 3GiB and 4GiB.
        if !region.overlap(&flash_range) {
            panic!("flash region in unexpected region");
        }

        // Make sure that no regions overlap with the kernel.
        if region.overlap(kernel_region) {
            panic!("flash region overlaps with kernel");
        }
    }

    // Make sure that regions don't overlap.
    for (i, outer) in flash_regions.iter().enumerate() {
        for inner in flash_regions[..i].iter() {
            if outer.overlap(inner) {
                panic!("flash regions overlap");
            }
        }
        // Make sure that one regions ends at 4GiB.
        let one_region_ends_at_4gib = flash_regions
            .iter()
            .any(|region| region.end() == flash_range.end());
        assert!(one_region_ends_at_4gib);
    }
}

#[derive(Debug)]
pub struct SvsmConfig<'a> {
    fw_cfg: Option<FwCfg<'a>>,
    igvm_params: IgvmParams<'a>,
}

impl<'a> SvsmConfig<'a> {
    pub fn new(platform: &dyn SvsmPlatform, igvm_params: IgvmParams<'a>) -> SvsmConfig<'a> {
        // Create a firmware config object if the IGVM parameter block
        // indicates that firmwrae config services are available on this
        // system.
        let fw_cfg = if igvm_params.has_fw_cfg_port() {
            let io_port = platform.get_io_port();
            Some(FwCfg::new(io_port))
        } else {
            None
        };
        Self {
            igvm_params,
            fw_cfg,
        }
    }

    pub fn get_igvm_params(&self) -> &IgvmParams<'_> {
        &self.igvm_params
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
        // This may fail if the MADT was not supplied via IGVM parameter
        // injection.  In this case, fall back to firmware config.  This will
        // panic if firmware config services are unavailable.
        if let Some(cpu_info) = self.igvm_params.load_cpu_info()? {
            Ok(cpu_info)
        } else {
            load_fw_cpu_info(self.fw_cfg.as_ref().unwrap())
        }
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
        let flash_regions = self.igvm_params.get_fw_regions();
        if !self.igvm_params.fw_in_low_memory() {
            check_ovmf_regions(&flash_regions, kernel_region);
        }
        flash_regions
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
