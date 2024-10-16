// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::console::init_svsm_console;
use crate::cpu::cpuid::{cpuid_table, CpuidResult};
use crate::cpu::percpu::{current_ghcb, this_cpu, PerCpu};
use crate::error::ApicError::Registration;
use crate::error::SvsmError;
use crate::greq::driver::guest_request_driver_init;
use crate::hyperv;
use crate::io::IOPort;
use crate::mm::{PerCPUPageMappingGuard, PAGE_SIZE, PAGE_SIZE_2M};
use crate::platform::{PageEncryptionMasks, PageStateChangeOp, PageValidateOp, SvsmPlatform};
use crate::sev::ghcb::GHCBIOSize;
use crate::sev::hv_doorbell::current_hv_doorbell;
use crate::sev::msr_protocol::{
    hypervisor_ghcb_features, request_termination_msr, verify_ghcb_version, GHCBHvFeatures,
};
use crate::sev::status::{sev_restricted_injection, vtom_enabled};
use crate::sev::{
    init_hypervisor_ghcb_features, pvalidate_range, sev_status_init, sev_status_verify, PvalidateOp,
};
use crate::types::PageSize;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::MemoryRegion;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static SVSM_ENV_INITIALIZED: AtomicBool = AtomicBool::new(false);

static GHCB_IO_DRIVER: GHCBIOPort = GHCBIOPort::new();

static VTOM: ImmutAfterInitCell<usize> = ImmutAfterInitCell::uninit();

static APIC_EMULATION_REG_COUNT: AtomicU32 = AtomicU32::new(0);

fn pvalidate_page_range(range: MemoryRegion<PhysAddr>, op: PvalidateOp) -> Result<(), SvsmError> {
    // In the future, it is likely that this function will need to be prepared
    // to execute both PVALIDATE and RMPADJUST over the same set of addresses,
    // so the loop is structured to anticipate that possibility.
    let mut paddr = range.start();
    let paddr_end = range.end();
    while paddr < paddr_end {
        // Check whether a 2 MB page can be attempted.
        let len = if paddr.is_aligned(PAGE_SIZE_2M) && paddr + PAGE_SIZE_2M <= paddr_end {
            PAGE_SIZE_2M
        } else {
            PAGE_SIZE
        };
        let mapping = PerCPUPageMappingGuard::create(paddr, paddr + len, 0)?;
        pvalidate_range(MemoryRegion::new(mapping.virt_addr(), len), op)?;
        paddr = paddr + len;
    }

    Ok(())
}

impl From<PageValidateOp> for PvalidateOp {
    fn from(op: PageValidateOp) -> PvalidateOp {
        match op {
            PageValidateOp::Validate => PvalidateOp::Valid,
            PageValidateOp::Invalidate => PvalidateOp::Invalid,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SnpPlatform {
    can_use_interrupts: bool,
}

impl SnpPlatform {
    pub fn new() -> Self {
        Self {
            can_use_interrupts: false,
        }
    }
}

impl Default for SnpPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl SvsmPlatform for SnpPlatform {
    fn env_setup(&mut self, _debug_serial_port: u16, vtom: usize) -> Result<(), SvsmError> {
        sev_status_init();
        VTOM.init(&vtom).map_err(|_| SvsmError::PlatformInit)?;

        // Now that SEV status is initialized, determine whether this platform
        // supports the use of SVSM interrupts.  SVSM interrupts are supported
        // if this system uses restricted injection.
        if sev_restricted_injection() {
            self.can_use_interrupts = true;
        }

        Ok(())
    }

    fn env_setup_late(&mut self, debug_serial_port: u16) -> Result<(), SvsmError> {
        init_svsm_console(&GHCB_IO_DRIVER, debug_serial_port)?;
        sev_status_verify();
        init_hypervisor_ghcb_features()?;
        Ok(())
    }

    fn env_setup_svsm(&self) -> Result<(), SvsmError> {
        this_cpu().configure_hv_doorbell()?;
        guest_request_driver_init();
        SVSM_ENV_INITIALIZED.store(true, Ordering::Relaxed);
        Ok(())
    }

    fn setup_percpu(&self, cpu: &PerCpu) -> Result<(), SvsmError> {
        // Setup GHCB
        cpu.setup_ghcb()
    }

    fn setup_percpu_current(&self, cpu: &PerCpu) -> Result<(), SvsmError> {
        cpu.register_ghcb()?;

        // #HV doorbell allocation can only occur if the SVSM environment has
        // already been initialized.  Skip allocation if not; it will be done
        // during environment initialization.
        if SVSM_ENV_INITIALIZED.load(Ordering::Relaxed) {
            cpu.configure_hv_doorbell()?;
        }

        Ok(())
    }

    fn get_page_encryption_masks(&self) -> PageEncryptionMasks {
        // Find physical address size.
        let processor_capacity =
            cpuid_table(0x80000008).expect("Can not get physical address size from CPUID table");
        if vtom_enabled() {
            let vtom = *VTOM;
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

    fn cpuid(&self, eax: u32) -> Option<CpuidResult> {
        cpuid_table(eax)
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

    fn get_io_port(&self) -> &'static dyn IOPort {
        &GHCB_IO_DRIVER
    }

    fn page_state_change(
        &self,
        region: MemoryRegion<PhysAddr>,
        size: PageSize,
        op: PageStateChangeOp,
    ) -> Result<(), SvsmError> {
        current_ghcb().page_state_change(region, size, op)
    }

    fn validate_physical_page_range(
        &self,
        region: MemoryRegion<PhysAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        pvalidate_page_range(region, PvalidateOp::from(op))
    }

    fn validate_virtual_page_range(
        &self,
        region: MemoryRegion<VirtAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        pvalidate_range(region, PvalidateOp::from(op))
    }

    fn configure_alternate_injection(&mut self, alt_inj_requested: bool) -> Result<(), SvsmError> {
        if !alt_inj_requested {
            return Ok(());
        }

        // If alternate injection was requested, then it must be supported by
        // the hypervisor.
        if !hypervisor_ghcb_features().contains(GHCBHvFeatures::SEV_SNP_EXT_INTERRUPTS) {
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

    fn use_interrupts(&self) -> bool {
        self.can_use_interrupts
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

    fn is_external_interrupt(&self, _vector: usize) -> bool {
        // When restricted injection is active, the event disposition is
        // already known to the caller and thus need not be examined.  When
        // restricted injection is not active, the hypervisor must be trusted
        // with all event delivery, so all events are assumed not to be
        // external interrupts.
        false
    }

    fn start_cpu(
        &self,
        cpu: &PerCpu,
        context: &hyperv::HvInitialVpContext,
    ) -> Result<(), SvsmError> {
        let (vmsa_pa, sev_features) = cpu.alloc_svsm_vmsa(*VTOM as u64, context)?;

        current_ghcb().ap_create(vmsa_pa, cpu.get_apic_id().into(), 0, sev_features)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GHCBIOPort {}

impl GHCBIOPort {
    pub const fn new() -> Self {
        GHCBIOPort {}
    }
}

impl IOPort for GHCBIOPort {
    fn outb(&self, port: u16, value: u8) {
        let ret = current_ghcb().ioio_out(port, GHCBIOSize::Size8, value as u64);
        if ret.is_err() {
            request_termination_msr();
        }
    }

    fn inb(&self, port: u16) -> u8 {
        let ret = current_ghcb().ioio_in(port, GHCBIOSize::Size8);
        match ret {
            Ok(v) => (v & 0xff) as u8,
            Err(_e) => request_termination_msr(),
        }
    }

    fn outw(&self, port: u16, value: u16) {
        let ret = current_ghcb().ioio_out(port, GHCBIOSize::Size16, value as u64);
        if ret.is_err() {
            request_termination_msr();
        }
    }

    fn inw(&self, port: u16) -> u16 {
        let ret = current_ghcb().ioio_in(port, GHCBIOSize::Size16);
        match ret {
            Ok(v) => (v & 0xffff) as u16,
            Err(_e) => request_termination_msr(),
        }
    }

    fn outl(&self, port: u16, value: u32) {
        let ret = current_ghcb().ioio_out(port, GHCBIOSize::Size32, value as u64);
        if ret.is_err() {
            request_termination_msr();
        }
    }

    fn inl(&self, port: u16) -> u32 {
        let ret = current_ghcb().ioio_in(port, GHCBIOSize::Size32);
        match ret {
            Ok(v) => (v & 0xffffffff) as u32,
            Err(_e) => request_termination_msr(),
        }
    }
}
