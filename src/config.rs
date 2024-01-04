// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

extern crate alloc;

use crate::acpi::tables::{load_acpi_cpu_info, ACPICPUInfo};
use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::fw_cfg::FwCfg;
use crate::fw_meta::SevFWMetaData;
use crate::igvm_params::IgvmParams;
use crate::mm::{PAGE_SIZE, SIZE_1G};
use crate::serial::SERIAL_PORT;
use crate::utils::MemoryRegion;
use alloc::vec::Vec;

#[derive(Debug)]
pub enum SvsmConfig<'a> {
    FirmwareConfig(FwCfg<'a>),
    IgvmConfig(IgvmParams<'a>),
}

impl<'a> SvsmConfig<'a> {
    pub fn find_kernel_region(&self) -> Result<MemoryRegion<PhysAddr>, SvsmError> {
        match self {
            SvsmConfig::FirmwareConfig(fw_cfg) => fw_cfg.find_kernel_region(),
            SvsmConfig::IgvmConfig(igvm_params) => igvm_params.find_kernel_region(),
        }
    }
    pub fn get_cpuid_page_address(&self) -> u64 {
        match self {
            SvsmConfig::FirmwareConfig(_) => 0x9f000,
            SvsmConfig::IgvmConfig(igvm_params) => igvm_params.get_cpuid_page_address(),
        }
    }
    pub fn get_secrets_page_address(&self) -> u64 {
        match self {
            SvsmConfig::FirmwareConfig(_) => 0x9e000,
            SvsmConfig::IgvmConfig(igvm_params) => igvm_params.get_secrets_page_address(),
        }
    }
    pub fn page_state_change_required(&self) -> bool {
        match self {
            SvsmConfig::FirmwareConfig(_) => true,
            SvsmConfig::IgvmConfig(igvm_params) => igvm_params.page_state_change_required(),
        }
    }
    pub fn get_memory_regions(&self) -> Result<Vec<MemoryRegion<PhysAddr>>, SvsmError> {
        match self {
            SvsmConfig::FirmwareConfig(fw_cfg) => fw_cfg.get_memory_regions(),
            SvsmConfig::IgvmConfig(igvm_params) => igvm_params.get_memory_regions(),
        }
    }
    pub fn load_cpu_info(&self) -> Result<Vec<ACPICPUInfo>, SvsmError> {
        match self {
            SvsmConfig::FirmwareConfig(fw_cfg) => load_acpi_cpu_info(fw_cfg),
            SvsmConfig::IgvmConfig(igvm_params) => igvm_params.load_cpu_info(),
        }
    }
    pub fn should_launch_fw(&self) -> bool {
        match self {
            SvsmConfig::FirmwareConfig(_) => true,
            SvsmConfig::IgvmConfig(igvm_params) => igvm_params.should_launch_fw(),
        }
    }

    pub fn debug_serial_port(&self) -> u16 {
        match self {
            SvsmConfig::FirmwareConfig(_) => SERIAL_PORT,
            SvsmConfig::IgvmConfig(igvm_params) => igvm_params.debug_serial_port(),
        }
    }

    pub fn get_fw_metadata_address(&self) -> Option<PhysAddr> {
        match self {
            SvsmConfig::FirmwareConfig(_) => {
                // The metadata location always starts at 32 bytes below 4GB
                Some(PhysAddr::from((4 * SIZE_1G) - PAGE_SIZE))
            }
            SvsmConfig::IgvmConfig(igvm_params) => igvm_params.get_fw_metadata_address(),
        }
    }

    pub fn get_fw_metadata(&self) -> Option<SevFWMetaData> {
        match self {
            SvsmConfig::FirmwareConfig(_) => None,
            SvsmConfig::IgvmConfig(igvm_params) => igvm_params.get_fw_metadata(),
        }
    }

    pub fn get_fw_regions(&self) -> Result<Vec<MemoryRegion<PhysAddr>>, SvsmError> {
        match self {
            SvsmConfig::FirmwareConfig(fw_cfg) => {
                Ok(fw_cfg.iter_flash_regions().collect::<Vec<_>>())
            }
            SvsmConfig::IgvmConfig(igvm_params) => igvm_params.get_fw_regions(),
        }
    }

    pub fn invalidate_boot_data(&self) -> bool {
        match self {
            SvsmConfig::FirmwareConfig(_) => false,
            SvsmConfig::IgvmConfig(_) => true,
        }
    }
}
