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
use crate::utils::MemoryRegion;
use alloc::vec::Vec;

#[derive(Debug)]
pub enum SvsmConfig<'a> {
    FirmwareConfig(FwCfg<'a>),
}

impl<'a> SvsmConfig<'a> {
    pub fn find_kernel_region(&self) -> Result<MemoryRegion<PhysAddr>, SvsmError> {
        match self {
            SvsmConfig::FirmwareConfig(fw_cfg) => fw_cfg.find_kernel_region(),
        }
    }
    pub fn get_cpuid_page_address(&self) -> u64 {
        match self {
            SvsmConfig::FirmwareConfig(_) => 0x9f000,
        }
    }
    pub fn get_secrets_page_address(&self) -> u64 {
        match self {
            SvsmConfig::FirmwareConfig(_) => 0x9e000,
        }
    }
    pub fn page_state_change_required(&self) -> bool {
        true
    }
    pub fn get_memory_regions(&self) -> Result<Vec<MemoryRegion<PhysAddr>>, SvsmError> {
        match self {
            SvsmConfig::FirmwareConfig(fw_cfg) => fw_cfg.get_memory_regions(),
        }
    }
    pub fn load_cpu_info(&self) -> Result<Vec<ACPICPUInfo>, SvsmError> {
        match self {
            SvsmConfig::FirmwareConfig(fw_cfg) => load_acpi_cpu_info(fw_cfg),
        }
    }
}
