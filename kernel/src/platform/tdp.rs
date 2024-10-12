// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 Intel Corporation
//
// Author: Peter Fang <peter.fang@intel.com>

use crate::address::{PhysAddr, VirtAddr};
use crate::console::init_svsm_console;
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::percpu::PerCpu;
use crate::error::SvsmError;
use crate::io::{IOPort, DEFAULT_IO_DRIVER};
use crate::platform::{PageEncryptionMasks, PageStateChangeOp, PageValidateOp, SvsmPlatform};
use crate::types::PageSize;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::MemoryRegion;

static VTOM: ImmutAfterInitCell<usize> = ImmutAfterInitCell::uninit();

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
    fn env_setup(&mut self, _debug_serial_port: u16, vtom: usize) -> Result<(), SvsmError> {
        VTOM.init(&vtom).map_err(|_| SvsmError::PlatformInit)
    }

    fn env_setup_late(&mut self, debug_serial_port: u16) -> Result<(), SvsmError> {
        init_svsm_console(&DEFAULT_IO_DRIVER, debug_serial_port)
    }

    fn env_setup_svsm(&self) -> Result<(), SvsmError> {
        Ok(())
    }

    fn setup_percpu(&self, _cpu: &PerCpu) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn setup_percpu_current(&self, _cpu: &PerCpu) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn get_page_encryption_masks(&self) -> PageEncryptionMasks {
        // Find physical address size.
        let res = CpuidResult::get(0x80000008, 0);
        let vtom = *VTOM;
        PageEncryptionMasks {
            private_pte_mask: 0,
            shared_pte_mask: vtom,
            addr_mask_width: vtom.trailing_zeros(),
            phys_addr_sizes: res.eax & 0xff,
        }
    }

    fn cpuid(&self, eax: u32) -> Option<CpuidResult> {
        Some(CpuidResult::get(eax, 0))
    }

    fn setup_guest_host_comm(&mut self, _cpu: &PerCpu, _is_bsp: bool) {}

    fn get_io_port(&self) -> &'static dyn IOPort {
        // FIXME - the default I/O port implementation doesn't work on TDP,
        // but the platform does not yet have an alternative available.
        &DEFAULT_IO_DRIVER
    }

    fn page_state_change(
        &self,
        _region: MemoryRegion<PhysAddr>,
        _size: PageSize,
        _op: PageStateChangeOp,
    ) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn validate_physical_page_range(
        &self,
        _region: MemoryRegion<PhysAddr>,
        _op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn validate_virtual_page_range(
        &self,
        _region: MemoryRegion<VirtAddr>,
        _op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn configure_alternate_injection(&mut self, _alt_inj_requested: bool) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn change_apic_registration_state(&self, _incr: bool) -> Result<bool, SvsmError> {
        Err(SvsmError::NotSupported)
    }

    fn query_apic_registration_state(&self) -> bool {
        false
    }

    fn use_interrupts(&self) -> bool {
        true
    }

    fn post_irq(&self, _icr: u64) -> Result<(), SvsmError> {
        Err(SvsmError::Tdx)
    }

    fn eoi(&self) {}

    fn is_external_interrupt(&self, _vector: usize) -> bool {
        // Examine the APIC ISR to determine whether this interrupt vector is
        // active.  If so, it is assumed to be an external interrupt.
        // TODO - add code to read the APIC ISR.
        todo!();
    }

    fn start_cpu(&self, _cpu: &PerCpu, _start_rip: u64) -> Result<(), SvsmError> {
        todo!();
    }
}
