// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 Intel Corporation
//
// Author: Peter Fang <peter.fang@intel.com>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::console::init_svsm_console;
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::percpu::PerCpu;
use crate::error::SvsmError;
use crate::io::IOPort;
use crate::mm::virt_to_frame;
use crate::platform::{PageEncryptionMasks, PageStateChangeOp, PageValidateOp, SvsmPlatform};
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::MemoryRegion;
use tdx_tdcall::tdx::{
    td_accept_memory, tdvmcall_halt, tdvmcall_io_read_16, tdvmcall_io_read_32, tdvmcall_io_read_8,
    tdvmcall_io_write_16, tdvmcall_io_write_32, tdvmcall_io_write_8,
};

static GHCI_IO_DRIVER: GHCIIOPort = GHCIIOPort::new();
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
    fn halt() {
        tdvmcall_halt();
    }

    fn env_setup(&mut self, debug_serial_port: u16, vtom: usize) -> Result<(), SvsmError> {
        VTOM.init(&vtom).map_err(|_| SvsmError::PlatformInit)?;
        // Serial console device can be initialized immediately
        init_svsm_console(&GHCI_IO_DRIVER, debug_serial_port)
    }

    fn env_setup_late(&mut self, _debug_serial_port: u16) -> Result<(), SvsmError> {
        Ok(())
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
            phys_addr_sizes: res.eax,
        }
    }

    fn cpuid(&self, eax: u32) -> Option<CpuidResult> {
        Some(CpuidResult::get(eax, 0))
    }

    fn setup_guest_host_comm(&mut self, _cpu: &PerCpu, _is_bsp: bool) {}

    fn get_io_port(&self) -> &'static dyn IOPort {
        &GHCI_IO_DRIVER
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
        region: MemoryRegion<PhysAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        match op {
            PageValidateOp::Validate => {
                td_accept_memory(region.start().into(), region.len().try_into().unwrap());
            }
            PageValidateOp::Invalidate => {}
        }
        Ok(())
    }

    fn validate_virtual_page_range(
        &self,
        region: MemoryRegion<VirtAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        match op {
            PageValidateOp::Validate => {
                let mut va = region.start();
                let va_end = region.end();
                while va < va_end {
                    let frame = virt_to_frame(va);
                    // Validate a 2 MB page if and only if the addresses are
                    // appropriately aligned and the underlying mapping is a
                    // 2 MB mapping.
                    let size = if va.is_aligned(PAGE_SIZE_2M)
                        && va + PAGE_SIZE_2M <= va_end
                        && frame.size() >= PAGE_SIZE_2M
                    {
                        PAGE_SIZE_2M
                    } else {
                        PAGE_SIZE
                    };

                    td_accept_memory(frame.address().into(), size.try_into().unwrap());
                    va = va + size;
                }
            }
            PageValidateOp::Invalidate => {}
        }
        Ok(())
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

#[derive(Clone, Copy, Debug, Default)]
struct GHCIIOPort {}

impl GHCIIOPort {
    pub const fn new() -> Self {
        GHCIIOPort {}
    }
}

impl IOPort for GHCIIOPort {
    fn outb(&self, port: u16, value: u8) {
        tdvmcall_io_write_8(port, value);
    }

    fn inb(&self, port: u16) -> u8 {
        tdvmcall_io_read_8(port)
    }

    fn outw(&self, port: u16, value: u16) {
        tdvmcall_io_write_16(port, value);
    }

    fn inw(&self, port: u16) -> u16 {
        tdvmcall_io_read_16(port)
    }

    fn outl(&self, port: u16, value: u32) {
        tdvmcall_io_write_32(port, value);
    }

    fn inl(&self, port: u16) -> u32 {
        tdvmcall_io_read_32(port)
    }
}
