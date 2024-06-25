// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 Intel Corporation
//
// Author: Peter Fang <peter.fang@intel.com>

use crate::address::{PhysAddr, VirtAddr};
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::percpu::PerCpu;
use crate::error::SvsmError;
use crate::io::IOPort;
use crate::platform::{PageEncryptionMasks, PageStateChangeOp, SvsmPlatform};
use crate::svsm_console::SVSMIOPort;
use crate::types::PageSize;
use crate::utils::MemoryRegion;

static CONSOLE_IO: SVSMIOPort = SVSMIOPort::new();

#[derive(Clone, Copy, Debug)]
pub struct TdpPlatform {}

impl TdpPlatform {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for TdpPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl SvsmPlatform for TdpPlatform {
    fn env_setup(&mut self) {}

    fn env_setup_late(&mut self) {}

    fn setup_percpu(&self, _cpu: &PerCpu) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn setup_percpu_current(&self, _cpu: &PerCpu) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn get_page_encryption_masks(&self, vtom: usize) -> PageEncryptionMasks {
        // Find physical address size.
        let res = CpuidResult::get(0x80000008, 0);
        PageEncryptionMasks {
            private_pte_mask: 0,
            shared_pte_mask: vtom,
            addr_mask_width: vtom.trailing_zeros(),
            phys_addr_sizes: res.eax & 0xff,
        }
    }

    fn setup_guest_host_comm(&mut self, _cpu: &PerCpu, _is_bsp: bool) {}

    fn get_console_io_port(&self) -> &'static dyn IOPort {
        &CONSOLE_IO
    }

    fn page_state_change(
        &self,
        _region: MemoryRegion<PhysAddr>,
        _size: PageSize,
        _op: PageStateChangeOp,
    ) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn validate_page_range(&self, _region: MemoryRegion<VirtAddr>) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn invalidate_page_range(&self, _region: MemoryRegion<VirtAddr>) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn configure_alternate_injection(&mut self, _alt_inj_requested: bool) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn use_alternate_injection(&self) -> bool {
        false
    }

    fn lock_unlock_apic_emulation(&self, _lock: bool) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn disable_apic_emulation(&self) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn post_irq(&self, _icr: u64) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn eoi(&self) {}
}
