// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::cpu::cpuid::cpuid_table;
use crate::cpu::ghcb::current_ghcb;
use crate::cpu::percpu::PerCpu;
use crate::io::IOPort;
use crate::platform::{PageEncryptionMasks, PhysAddr, SvsmError, SvsmPlatform, VirtAddr};
use crate::sev::ghcb::PageStateChangeOp::{PscPrivate, PscShared};
use crate::sev::msr_protocol::verify_ghcb_version;
use crate::sev::status::vtom_enabled;
use crate::sev::{pvalidate_range, sev_status_init, sev_status_verify, PvalidateOp};
use crate::svsm_console::SVSMIOPort;
use crate::types::PageSize;
use crate::utils::MemoryRegion;

static CONSOLE_IO: SVSMIOPort = SVSMIOPort::new();

#[derive(Clone, Copy, Debug)]
pub struct SnpPlatform {}

impl SnpPlatform {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for SnpPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl SvsmPlatform for SnpPlatform {
    fn env_setup(&mut self) {
        sev_status_init();
    }

    fn env_setup_late(&mut self) {
        sev_status_verify();
    }

    fn setup_percpu(&self, cpu: &mut PerCpu) -> Result<(), SvsmError> {
        // Setup GHCB
        cpu.setup_ghcb()
    }

    fn setup_percpu_current(&self, cpu: &mut PerCpu) -> Result<(), SvsmError> {
        cpu.register_ghcb()
    }

    fn get_page_encryption_masks(&self, vtom: usize) -> PageEncryptionMasks {
        // Find physical address size.
        let res =
            cpuid_table(0x80000008).expect("Can not get physical address size from CPUID table");
        if vtom_enabled() {
            PageEncryptionMasks {
                private_pte_mask: 0,
                shared_pte_mask: vtom,
                addr_mask_width: vtom.leading_zeros(),
                phys_addr_sizes: res.eax,
            }
        } else {
            // Find C-bit position.
            let res = cpuid_table(0x8000001f).expect("Can not get C-Bit position from CPUID table");
            let c_bit = res.ebx & 0x3f;
            PageEncryptionMasks {
                private_pte_mask: 1 << c_bit,
                shared_pte_mask: 0,
                addr_mask_width: c_bit,
                phys_addr_sizes: res.eax,
            }
        }
    }

    fn setup_guest_host_comm(&mut self, cpu: &mut PerCpu, is_bsp: bool) {
        if is_bsp {
            verify_ghcb_version();
        }

        cpu.setup_ghcb().unwrap_or_else(|_| {
            if is_bsp {
                panic!("Failed to setup BSP GHCB");
            } else {
                panic!("Failed to setup AP GHCB");
            }
        });
        cpu.register_ghcb().expect("Failed to register GHCB");
    }

    fn get_console_io_port(&self) -> &'static dyn IOPort {
        &CONSOLE_IO
    }

    fn page_state_change(
        &self,
        start: PhysAddr,
        end: PhysAddr,
        size: PageSize,
        make_private: bool,
    ) -> Result<(), SvsmError> {
        let psc_op = if make_private { PscPrivate } else { PscShared };
        current_ghcb().page_state_change(start, end, size, psc_op)
    }

    fn pvalidate_range(
        &self,
        region: MemoryRegion<VirtAddr>,
        valid: bool,
    ) -> Result<(), SvsmError> {
        let pvalidate_op = if valid {
            PvalidateOp::Valid
        } else {
            PvalidateOp::Invalid
        };
        pvalidate_range(region, pvalidate_op)
    }
}
