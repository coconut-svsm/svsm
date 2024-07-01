// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::address::{PhysAddr, VirtAddr};
use crate::cpu::cpuid::cpuid_table;
use crate::cpu::percpu::{current_ghcb, PerCpu};
use crate::error::ApicError::Registration;
use crate::error::SvsmError;
use crate::io::IOPort;
use crate::platform::{PageEncryptionMasks, PageStateChangeOp, SvsmPlatform};
use crate::sev::hv_doorbell::current_hv_doorbell;
use crate::sev::msr_protocol::{hypervisor_ghcb_features, verify_ghcb_version, GHCBHvFeatures};
use crate::sev::status::vtom_enabled;
use crate::sev::{
    init_hypervisor_ghcb_features, pvalidate_range, sev_status_init, sev_status_verify, PvalidateOp,
};
use crate::svsm_console::SVSMIOPort;
use crate::types::PageSize;
use crate::utils::MemoryRegion;

use core::sync::atomic::{AtomicU32, Ordering};

static CONSOLE_IO: SVSMIOPort = SVSMIOPort::new();

static APIC_EMULATION_REG_COUNT: AtomicU32 = AtomicU32::new(0);

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
        init_hypervisor_ghcb_features().expect("Failed to obtain hypervisor GHCB features");
    }

    fn setup_percpu(&self, cpu: &PerCpu) -> Result<(), SvsmError> {
        // Setup GHCB
        cpu.setup_ghcb()
    }

    fn setup_percpu_current(&self, cpu: &PerCpu) -> Result<(), SvsmError> {
        cpu.register_ghcb()?;
        Ok(())
    }

    fn get_page_encryption_masks(&self, vtom: usize) -> PageEncryptionMasks {
        // Find physical address size.
        let processor_capacity =
            cpuid_table(0x80000008).expect("Can not get physical address size from CPUID table");
        if vtom_enabled() {
            PageEncryptionMasks {
                private_pte_mask: 0,
                shared_pte_mask: vtom,
                addr_mask_width: vtom.leading_zeros(),
                phys_addr_sizes: processor_capacity.eax,
            }
        } else {
            // Find C-bit position.
            let sev_capabilities =
                cpuid_table(0x8000001f).expect("Can not get C-Bit position from CPUID table");
            let c_bit = sev_capabilities.ebx & 0x3f;
            PageEncryptionMasks {
                private_pte_mask: 1 << c_bit,
                shared_pte_mask: 0,
                addr_mask_width: c_bit,
                phys_addr_sizes: processor_capacity.eax,
            }
        }
    }

    fn setup_guest_host_comm(&mut self, cpu: &PerCpu, is_bsp: bool) {
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
        region: MemoryRegion<PhysAddr>,
        size: PageSize,
        op: PageStateChangeOp,
    ) -> Result<(), SvsmError> {
        current_ghcb().page_state_change(region, size, op)
    }

    /// Marks a range of pages as valid for use as private pages.
    fn validate_page_range(&self, region: MemoryRegion<VirtAddr>) -> Result<(), SvsmError> {
        pvalidate_range(region, PvalidateOp::Valid)
    }

    /// Marks a range of pages as invalid for use as private pages.
    fn invalidate_page_range(&self, region: MemoryRegion<VirtAddr>) -> Result<(), SvsmError> {
        pvalidate_range(region, PvalidateOp::Invalid)
    }

    fn configure_alternate_injection(&mut self, alt_inj_requested: bool) -> Result<(), SvsmError> {
        // If alternate injection was requested, then it must be supported by
        // the hypervisor.
        if alt_inj_requested
            && !hypervisor_ghcb_features().contains(GHCBHvFeatures::SEV_SNP_EXT_INTERRUPTS)
        {
            return Err(SvsmError::NotSupported);
        }

        APIC_EMULATION_REG_COUNT.store(1, Ordering::Relaxed);
        Ok(())
    }

    fn change_apic_registration_state(&self, incr: bool) -> Result<bool, SvsmError> {
        let mut current = APIC_EMULATION_REG_COUNT.load(Ordering::Relaxed);
        loop {
            let new = if incr {
                // Incrementing is only possible if the registration count
                // has not already dropped to zero, and only if the
                // registration count will not wrap around.
                if current == 0 {
                    return Err(SvsmError::Apic(Registration));
                }
                current
                    .checked_add(1)
                    .ok_or(SvsmError::Apic(Registration))?
            } else {
                // An attempt to decrement when the count is already zero is
                // considered a benign race, which will not result in any
                // actual change but will indicate that emulation is being
                // disabled for the guest.
                if current == 0 {
                    return Ok(false);
                }
                current - 1
            };
            match APIC_EMULATION_REG_COUNT.compare_exchange_weak(
                current,
                new,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(new > 0);
                }
                Err(val) => current = val,
            }
        }
    }

    fn query_apic_registration_state(&self) -> bool {
        APIC_EMULATION_REG_COUNT.load(Ordering::Relaxed) > 0
    }

    fn post_irq(&self, icr: u64) -> Result<(), SvsmError> {
        current_ghcb().hv_ipi(icr)?;
        Ok(())
    }

    fn eoi(&self) {
        // Issue an explicit EOI unless no explicit EOI is required.
        if !current_hv_doorbell().no_eoi_required() {
            // 0x80B is the X2APIC EOI MSR.
            // Errors here cannot be handled but should not be grounds for
            // panic.
            let _ = current_ghcb().wrmsr(0x80B, 0);
        }
    }
}
