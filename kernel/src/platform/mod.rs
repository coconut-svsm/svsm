// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

pub mod guest_cpu;
pub mod native;
pub mod snp;
pub mod tdp;

mod snp_fw;
pub use snp_fw::{parse_fw_meta_data, SevFWMetaData};

use native::NativePlatform;
use snp::SnpPlatform;
use tdp::TdpPlatform;

use core::arch::asm;
use core::ops::{Deref, DerefMut};

use crate::address::{PhysAddr, VirtAddr};
use crate::config::SvsmConfig;
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::percpu::PerCpu;
use crate::cpu::tlb::{flush_tlb, TlbFlushScope};
use crate::error::SvsmError;
use crate::hyperv;
use crate::io::IOPort;
use crate::types::PageSize;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::MemoryRegion;

use bootlib::platform::SvsmPlatformType;

static SVSM_PLATFORM_TYPE: ImmutAfterInitCell<SvsmPlatformType> = ImmutAfterInitCell::uninit();
pub static SVSM_PLATFORM: ImmutAfterInitCell<SvsmPlatformCell> = ImmutAfterInitCell::uninit();

#[derive(Clone, Copy, Debug)]
pub struct PageEncryptionMasks {
    pub private_pte_mask: usize,
    pub shared_pte_mask: usize,
    pub addr_mask_width: u32,
    pub phys_addr_sizes: u32,
}

#[derive(Debug, Clone, Copy)]
pub enum PageStateChangeOp {
    Private,
    Shared,
    Psmash,
    Unsmash,
}

#[derive(Debug, Clone, Copy)]
pub enum PageValidateOp {
    Validate,
    Invalidate,
}

/// This defines a platform abstraction to permit the SVSM to run on different
/// underlying architectures.
pub trait SvsmPlatform {
    #[cfg(test)]
    fn platform_type(&self) -> SvsmPlatformType;

    /// Halts the system as required by the platform.
    fn halt()
    where
        Self: Sized,
    {
        // SAFETY: executing HLT in assembly is always safe.
        unsafe {
            asm!("hlt");
        }
    }

    /// Performs basic early initialization of the runtime environment.
    fn env_setup(&mut self, debug_serial_port: u16, vtom: usize) -> Result<(), SvsmError>;

    /// Performs initialization of the platform runtime environment after
    /// the core system environment has been initialized.
    fn env_setup_late(&mut self, debug_serial_port: u16) -> Result<(), SvsmError>;

    /// Performs initialiation of the environment specfic to the SVSM kernel
    /// (for services not used by stage2).
    fn env_setup_svsm(&self) -> Result<(), SvsmError>;

    /// Performs the necessary preparations for launching guest boot firmware.
    fn prepare_fw(
        &self,
        _config: &SvsmConfig<'_>,
        _kernel_region: MemoryRegion<PhysAddr>,
    ) -> Result<(), SvsmError> {
        Ok(())
    }

    /// Launches guest boot firmware.
    fn launch_fw(&self, _config: &SvsmConfig<'_>) -> Result<(), SvsmError> {
        Ok(())
    }

    /// Completes initialization of a per-CPU object during construction.
    fn setup_percpu(&self, cpu: &PerCpu) -> Result<(), SvsmError>;

    /// Completes initialization of a per-CPU object on the target CPU.
    fn setup_percpu_current(&self, cpu: &PerCpu) -> Result<(), SvsmError>;

    /// Determines the paging encryption masks for the current architecture.
    fn get_page_encryption_masks(&self) -> PageEncryptionMasks;

    /// Obtain CPUID using platform-specific tables.
    fn cpuid(&self, eax: u32) -> Option<CpuidResult>;

    /// Establishes state required for guest/host communication.
    fn setup_guest_host_comm(&mut self, cpu: &PerCpu, is_bsp: bool);

    /// Obtains a reference to an I/O port implemetation appropriate to the
    /// platform.
    fn get_io_port(&self) -> &'static dyn IOPort;

    /// Performs a page state change between private and shared states.
    fn page_state_change(
        &self,
        region: MemoryRegion<PhysAddr>,
        size: PageSize,
        op: PageStateChangeOp,
    ) -> Result<(), SvsmError>;

    /// Marks a physical range of pages as valid or invalid for use as private
    /// pages.  Not usable in stage2.
    fn validate_physical_page_range(
        &self,
        region: MemoryRegion<PhysAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError>;

    /// Marks a virtual range of pages as valid or invalid for use as private
    /// pages.  Provided primarily for use in stage2 where validation by
    /// physical address cannot be supported.
    fn validate_virtual_page_range(
        &self,
        region: MemoryRegion<VirtAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError>;

    /// Performs a system-wide TLB flush.
    fn flush_tlb(&self, flush_scope: &TlbFlushScope) {
        flush_tlb(flush_scope);
    }

    /// Configures the use of alternate injection as requested.
    fn configure_alternate_injection(&mut self, alt_inj_requested: bool) -> Result<(), SvsmError>;

    /// Changes the state of APIC registration on this system, returning either
    /// the current registration state or an error.
    fn change_apic_registration_state(&self, incr: bool) -> Result<bool, SvsmError>;

    /// Queries the state of APIC registration on this system.
    fn query_apic_registration_state(&self) -> bool;

    /// Determines whether the platform supports interrupts to the SVSM.
    fn use_interrupts(&self) -> bool;

    /// Signal an IRQ on one or more CPUs.
    fn post_irq(&self, icr: u64) -> Result<(), SvsmError>;

    /// Perform an EOI of the current interrupt.
    fn eoi(&self);

    /// Determines whether a given interrupt vector was invoked as an external
    /// interrupt.
    fn is_external_interrupt(&self, vector: usize) -> bool;

    /// Start an additional processor.
    fn start_cpu(
        &self,
        cpu: &PerCpu,
        context: &hyperv::HvInitialVpContext,
    ) -> Result<(), SvsmError>;
}

//FIXME - remove Copy trait
#[derive(Clone, Copy, Debug)]
pub enum SvsmPlatformCell {
    Snp(SnpPlatform),
    Tdp(TdpPlatform),
    Native(NativePlatform),
}

impl SvsmPlatformCell {
    pub fn new(platform_type: SvsmPlatformType, suppress_svsm_interrupts: bool) -> Self {
        assert_eq!(platform_type, *SVSM_PLATFORM_TYPE);
        match platform_type {
            SvsmPlatformType::Native => {
                SvsmPlatformCell::Native(NativePlatform::new(suppress_svsm_interrupts))
            }
            SvsmPlatformType::Snp => {
                SvsmPlatformCell::Snp(SnpPlatform::new(suppress_svsm_interrupts))
            }
            SvsmPlatformType::Tdp => {
                SvsmPlatformCell::Tdp(TdpPlatform::new(suppress_svsm_interrupts))
            }
        }
    }
}

impl Deref for SvsmPlatformCell {
    type Target = dyn SvsmPlatform;

    fn deref(&self) -> &Self::Target {
        match self {
            SvsmPlatformCell::Native(platform) => platform,
            SvsmPlatformCell::Snp(platform) => platform,
            SvsmPlatformCell::Tdp(platform) => platform,
        }
    }
}

impl DerefMut for SvsmPlatformCell {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            SvsmPlatformCell::Native(platform) => platform,
            SvsmPlatformCell::Snp(platform) => platform,
            SvsmPlatformCell::Tdp(platform) => platform,
        }
    }
}

pub fn init_platform_type(platform_type: SvsmPlatformType) {
    SVSM_PLATFORM_TYPE.init(platform_type).unwrap();
}

pub fn halt() {
    // Use a platform-specific halt.  However, the SVSM_PLATFORM global may not
    // yet be initialized, so go choose the halt implementation based on the
    // platform-specific halt instead.
    match *SVSM_PLATFORM_TYPE {
        SvsmPlatformType::Native => NativePlatform::halt(),
        SvsmPlatformType::Snp => SnpPlatform::halt(),
        SvsmPlatformType::Tdp => TdpPlatform::halt(),
    }
}
