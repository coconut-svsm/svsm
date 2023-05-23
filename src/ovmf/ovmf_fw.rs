// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use crate::address::PhysAddr;
use crate::cpu::percpu::this_cpu_mut;
use crate::error::SvsmError;
use crate::requests::update_mappings;
use crate::types::GUEST_VMPL;

use super::{parse_ovmf_meta_data, print_ovmf_meta, validate_ovmf_memory, SevOVMFMetaData};

/*
 * The EDK2 OvmfSvsmX64 platform creates a reset vector with the entry point and metadata
 * for the SVSM module at 4K below 4GB and the OVMF entry point and metadata at 8K below
 * 4GB.
*/
const OVMF_ENTRY: u64 = 0xffffeff0;

pub struct OvmfFw {
    ovmf_meta: SevOVMFMetaData,
}

impl OvmfFw {
    pub fn new() -> Self {
        let ovmf_meta = parse_ovmf_meta_data()
            .unwrap_or_else(|e| panic!("Failed to parse OVMF FW SEV meta-data: {:#?}", e));
        print_ovmf_meta(&ovmf_meta);

        if let Err(e) = validate_ovmf_memory(&ovmf_meta) {
            panic!("Failed to validate firmware memory: {:#?}", e);
        }

        Self { ovmf_meta }
    }

    pub fn tables(self: &Self) -> (PhysAddr, PhysAddr, PhysAddr) {
        let cpuid_page = match self.ovmf_meta.cpuid_page {
            Some(addr) => addr,
            None => panic!("OVMF FW does not specify CPUID_PAGE location"),
        };

        let secrets_page = match self.ovmf_meta.secrets_page {
            Some(addr) => addr,
            None => panic!("OVMF FW does not specify SECRETS_PAGE location"),
        };

        let caa_page = match self.ovmf_meta.caa_page {
            Some(addr) => addr,
            None => panic!("OVMF FW does not specify CAA_PAGE location"),
        };
        (cpuid_page, secrets_page, caa_page)
    }

    pub fn prepare_launch(self: &Self) -> Result<(), SvsmError> {
        let caa = self.ovmf_meta.caa_page.unwrap();
        let cpu = this_cpu_mut();
        cpu.set_reset_ip(OVMF_ENTRY);

        cpu.alloc_guest_vmsa()?;
        cpu.update_guest_caa(caa);
        update_mappings()?;

        Ok(())
    }

    pub fn launch(self: &Self) -> Result<(), SvsmError> {
        let vmsa_pa = this_cpu_mut().guest_vmsa_ref().vmsa_phys().unwrap();
        let vmsa = this_cpu_mut().guest_vmsa();

        log::info!("VMSA PA: {:#x}", vmsa_pa);

        vmsa.enable();
        let sev_features = vmsa.sev_features;

        log::info!("Launching Firmware");
        this_cpu_mut()
            .ghcb()
            .ap_create(vmsa_pa, 0, GUEST_VMPL as u64, sev_features)?;

        Ok(())
    }
}
