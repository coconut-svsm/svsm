// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

extern crate alloc;

use core::slice;

use crate::acpi::tables::{load_fw_cpu_info, ACPICPUInfo};
use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::fw_cfg::FwCfg;
use crate::igvm_params::IgvmParams;
use crate::mm::{PerCPUPageMappingGuard, PAGE_SIZE, SIZE_1G};
use crate::platform::{parse_fw_meta_data, SevFWMetaData, SvsmPlatform};
use crate::serial::SERIAL_PORT;
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
    igvm_params: Option<IgvmParams<'a>>,
}

impl<'a> SvsmConfig<'a> {
    pub fn new(platform: &dyn SvsmPlatform, igvm_params: Option<IgvmParams<'a>>) -> SvsmConfig<'a> {
        // Create a firmware config object if there is no IGVM parameter block,
        // or if the IGVM parameter block indicates that firmwrae config
        // services are available on this system.
        let is_qemu = if let Some(ref igvm) = igvm_params {
            igvm.is_qemu()
        } else {
            true
        };
        let fw_cfg = if is_qemu {
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

    pub fn get_igvm_params(&self) -> Option<&IgvmParams<'_>> {
        self.igvm_params.as_ref()
    }

    pub fn find_kernel_region(&self) -> Result<MemoryRegion<PhysAddr>, SvsmError> {
        match &self.igvm_params {
            Some(igvm_params) => igvm_params.find_kernel_region(),
            None => self.fw_cfg.as_ref().unwrap().find_kernel_region(),
        }
    }
    pub fn page_state_change_required(&self) -> bool {
        match &self.igvm_params {
            Some(igvm_params) => igvm_params.page_state_change_required(),
            None => true,
        }
    }
    pub fn get_memory_regions(&self) -> Result<Vec<MemoryRegion<PhysAddr>>, SvsmError> {
        match &self.igvm_params {
            Some(igvm_params) => igvm_params.get_memory_regions(),
            None => self.fw_cfg.as_ref().unwrap().get_memory_regions(),
        }
    }
    pub fn write_guest_memory_map(&self, map: &[MemoryRegion<PhysAddr>]) -> Result<(), SvsmError> {
        match &self.igvm_params {
            Some(igvm_params) => igvm_params.write_guest_memory_map(map),
            None => Ok(()),
        }
    }
    pub fn reserved_kernel_area_size(&self) -> usize {
        match &self.igvm_params {
            Some(igvm_params) => igvm_params.reserved_kernel_area_size(),
            None => 0,
        }
    }
    pub fn load_cpu_info(&self) -> Result<Vec<ACPICPUInfo>, SvsmError> {
        // If IGVM parameters are present, then attempt to collect the CPU
        // information from the IGVM parameters.  Otherwise, fall back to
        // firmware config.
        if let Some(igvm_params) = &self.igvm_params {
            if let Some(cpu_info) = igvm_params.load_cpu_info()? {
                return Ok(cpu_info);
            }
        }

        load_fw_cpu_info(self.fw_cfg.as_ref().unwrap())
    }

    pub fn should_launch_fw(&self) -> bool {
        match &self.igvm_params {
            Some(igvm_params) => igvm_params.should_launch_fw(),
            None => true,
        }
    }

    pub fn debug_serial_port(&self) -> u16 {
        match &self.igvm_params {
            Some(igvm_params) => igvm_params.debug_serial_port(),
            None => SERIAL_PORT,
        }
    }

    pub fn get_fw_metadata(&self) -> Option<SevFWMetaData> {
        match &self.igvm_params {
            Some(igvm_params) => igvm_params.get_fw_metadata(),
            None => {
                // Map the metadata location which is defined by the firmware config
                let guard =
                    PerCPUPageMappingGuard::create_4k(PhysAddr::from(4 * SIZE_1G - PAGE_SIZE))
                        .expect("Failed to map FW metadata page");
                let vstart = guard.virt_addr().as_ptr::<u8>();
                // Safety: we just mapped a page, so the size must hold. The type
                // of the slice elements is `u8` so there are no alignment requirements.
                let metadata = unsafe { slice::from_raw_parts(vstart, PAGE_SIZE) };
                Some(parse_fw_meta_data(metadata).expect("Failed to parse FW SEV meta-data"))
            }
        }
    }

    pub fn get_fw_regions(
        &self,
        kernel_region: &MemoryRegion<PhysAddr>,
    ) -> Vec<MemoryRegion<PhysAddr>> {
        match &self.igvm_params {
            Some(igvm_params) => {
                let flash_regions = igvm_params.get_fw_regions();
                if !igvm_params.fw_in_low_memory() {
                    check_ovmf_regions(&flash_regions, kernel_region);
                }
                flash_regions
            }
            None => {
                let flash_regions = self
                    .fw_cfg
                    .as_ref()
                    .unwrap()
                    .iter_flash_regions()
                    .collect::<Vec<_>>();
                check_ovmf_regions(&flash_regions, kernel_region);
                flash_regions
            }
        }
    }

    pub fn fw_in_low_memory(&self) -> bool {
        match &self.igvm_params {
            Some(igvm_params) => igvm_params.fw_in_low_memory(),
            None => false,
        }
    }

    pub fn invalidate_boot_data(&self) -> bool {
        // Boot data should be invalidated if and only if IGVM parameters were
        // present.
        self.igvm_params.is_some()
    }

    pub fn initialize_guest_vmsa(&self, vmsa: &mut VMSA) -> Result<(), SvsmError> {
        match &self.igvm_params {
            Some(igvm_params) => igvm_params.initialize_guest_vmsa(vmsa),
            None => Ok(()),
        }
    }

    pub fn use_alternate_injection(&self) -> bool {
        match &self.igvm_params {
            Some(igvm_params) => igvm_params.use_alternate_injection(),
            None => false,
        }
    }

    pub fn is_qemu(&self) -> bool {
        match &self.igvm_params {
            Some(igvm_params) => igvm_params.is_qemu(),
            None => true,
        }
    }
}
