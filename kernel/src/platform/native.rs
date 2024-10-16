// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::address::{PhysAddr, VirtAddr};
use crate::console::init_svsm_console;
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::msr::write_msr;
use crate::cpu::percpu::PerCpu;
use crate::error::SvsmError;
use crate::hyperv::{hyperv_setup_hypercalls, is_hyperv_hypervisor};
use crate::io::{IOPort, DEFAULT_IO_DRIVER};
use crate::platform::{PageEncryptionMasks, PageStateChangeOp, PageValidateOp, SvsmPlatform};
use crate::types::PageSize;
use crate::utils::MemoryRegion;

#[cfg(debug_assertions)]
use crate::mm::virt_to_phys;

const APIC_MSR_ICR: u32 = 0x830;

#[derive(Clone, Copy, Debug)]
pub struct NativePlatform {
    is_hyperv: bool,
}

impl NativePlatform {
    pub fn new() -> Self {
        Self {
            is_hyperv: is_hyperv_hypervisor(),
        }
    }
}

impl Default for NativePlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl SvsmPlatform for NativePlatform {
    fn env_setup(&mut self, debug_serial_port: u16, _vtom: usize) -> Result<(), SvsmError> {
        // In the native platform, console output does not require the use of
        // any platform services, so it can be initialized immediately.
        init_svsm_console(&DEFAULT_IO_DRIVER, debug_serial_port)
    }

    fn env_setup_late(&mut self, _debug_serial_port: u16) -> Result<(), SvsmError> {
        Ok(())
    }

    fn env_setup_svsm(&self) -> Result<(), SvsmError> {
        if self.is_hyperv {
            hyperv_setup_hypercalls()?;
        }

        Ok(())
    }

    fn setup_percpu(&self, cpu: &PerCpu) -> Result<(), SvsmError> {
        if self.is_hyperv {
            cpu.allocate_hypercall_pages()?;
        }

        Ok(())
    }

    fn setup_percpu_current(&self, _cpu: &PerCpu) -> Result<(), SvsmError> {
        Ok(())
    }

    fn get_page_encryption_masks(&self) -> PageEncryptionMasks {
        // Find physical address size.
        let res = CpuidResult::get(0x80000008, 0);
        PageEncryptionMasks {
            private_pte_mask: 0,
            shared_pte_mask: 0,
            addr_mask_width: 64,
            phys_addr_sizes: res.eax,
        }
    }

    fn cpuid(&self, eax: u32) -> Option<CpuidResult> {
        Some(CpuidResult::get(eax, 0))
    }

    fn setup_guest_host_comm(&mut self, _cpu: &PerCpu, _is_bsp: bool) {}

    fn get_io_port(&self) -> &'static dyn IOPort {
        &DEFAULT_IO_DRIVER
    }

    fn page_state_change(
        &self,
        _region: MemoryRegion<PhysAddr>,
        _size: PageSize,
        _op: PageStateChangeOp,
    ) -> Result<(), SvsmError> {
        Ok(())
    }

    fn validate_physical_page_range(
        &self,
        _region: MemoryRegion<PhysAddr>,
        _op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        Ok(())
    }

    fn validate_virtual_page_range(
        &self,
        _region: MemoryRegion<VirtAddr>,
        _op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        #[cfg(debug_assertions)]
        {
            // Ensure that it is possible to translate this virtual address to
            // a physical address.  This is not necessary for correctness
            // here, but since other platformss may rely on virtual-to-physical
            // translation, it is helpful to force a translation here for
            // debugging purposes just to help catch potential errors when
            // testing on native.
            for va in _region.iter_pages(PageSize::Regular) {
                let _ = virt_to_phys(va);
            }
        }
        Ok(())
    }

    fn configure_alternate_injection(&mut self, _alt_inj_requested: bool) -> Result<(), SvsmError> {
        Ok(())
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

    fn post_irq(&self, icr: u64) -> Result<(), SvsmError> {
        write_msr(APIC_MSR_ICR, icr);
        Ok(())
    }

    fn eoi(&self) {
        todo!();
    }

    fn is_external_interrupt(&self, _vector: usize) -> bool {
        // For a native platform, the hypervisor is fully trusted with all
        // event delivery, so all events are assumed not to be external
        // interrupts.
        false
    }

    fn start_cpu(&self, _cpu: &PerCpu, _start_rip: u64) -> Result<(), SvsmError> {
        todo!();
    }
}
