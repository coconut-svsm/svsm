// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

pub mod capabilities;
pub mod guest_cpu;
pub mod native;
pub mod snp;
pub mod tdp;

mod snp_fw;
pub use snp_fw::SevFWMetaData;

use capabilities::Caps;
use native::{NativePlatform, NativeStage2Platform};
use snp::{SnpPlatform, SnpStage2Platform};
use tdp::{TdpPlatform, TdpStage2Platform};

use core::arch::asm;
use core::fmt::Debug;
use core::mem::MaybeUninit;

use crate::address::{PhysAddr, VirtAddr};
use crate::boot_params::BootParams;
use crate::cpu::IrqGuard;
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::percpu::PerCpu;
use crate::cpu::shadow_stack::determine_cet_support_from_cpuid;
use crate::cpu::tlb::{TlbFlushScope, flush_tlb};
use crate::error::SvsmError;
use crate::hyperv;
use crate::io::IOPort;
use crate::mm::TransitionPageTable;
use crate::mm::alloc::free_page;
use crate::utils::MemoryRegion;
use crate::utils::immut_after_init::ImmutAfterInitCell;

use bootdefs::kernel_launch::Stage2LaunchInfo;
use bootdefs::platform::SvsmPlatformType;

static SVSM_PLATFORM_TYPE: ImmutAfterInitCell<SvsmPlatformType> = ImmutAfterInitCell::uninit();
static SVSM_PLATFORM_CELL: ImmutAfterInitCell<SvsmPlatformCell> = ImmutAfterInitCell::uninit();
pub static SVSM_PLATFORM: ImmutAfterInitCell<&dyn SvsmPlatform> = ImmutAfterInitCell::uninit();
pub static CAPS: ImmutAfterInitCell<Caps> = ImmutAfterInitCell::uninit();

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

#[derive(Debug, Clone, Copy)]
pub enum PlatformPageType {
    Cpuid,
    Secrets,
}

/// This defines a platform abstraction to permit the SVSM to run on different
/// underlying architectures.
pub trait SvsmPlatform: Sync {
    #[cfg(test)]
    fn platform_type(&self) -> SvsmPlatformType;

    /// Halts the system required by the platform.  Interrupt state is under
    /// control of the caller.
    fn halt()
    where
        Self: Sized,
    {
        // SAFETY: executing HLT in assembly is always safe.
        unsafe {
            asm!("hlt");
        }
    }

    /// Halts the system with interrupts enabled as required by the platform.
    /// # Arguments
    /// _irq_guard: an IRQ guard structure.  This is not actually used, but
    /// serves as proof that interrupts have been correctly disabled so that
    /// interrupt state can be correctly manipulated as required by the idle
    /// halt action.
    fn idle_halt(&self, _irq_guard: &IrqGuard);

    /// Performs basic early initialization of the runtime environment.
    fn env_setup(&mut self, debug_serial_port: u16, vtom: usize) -> Result<(), SvsmError>;

    /// Initializes a platform-specific page.
    /// # Safety
    /// The caller must specify a valid virtual address for the specified type
    /// of page.
    unsafe fn initialize_platform_page(&self, _page_type: PlatformPageType, _vaddr: VirtAddr) {
        // By default, no action is required.
    }

    /// Performs initialization of the platform runtime environment after
    /// the core system environment has been initialized.
    fn env_setup_late(&mut self, debug_serial_port: u16) -> Result<(), SvsmError>;

    /// Performs initialiation of the environment specfic to the SVSM kernel
    /// (for services not used by stage2).
    fn env_setup_svsm(&self) -> Result<(), SvsmError>;

    /// Frees a platforms-specific page if it is not used by the underlying
    /// platform.
    /// # Safety
    /// The caller must specify a valid virtual address for the specified type
    /// of page.
    unsafe fn free_unused_platform_page(&self, _page_type: PlatformPageType, vaddr: VirtAddr) {
        free_page(vaddr);
    }

    /// Performs the necessary preparations for launching guest boot firmware.
    fn prepare_fw(
        &self,
        _boot_params: &BootParams<'_>,
        _kernel_region: MemoryRegion<PhysAddr>,
    ) -> Result<(), SvsmError> {
        Ok(())
    }

    /// Launches guest boot firmware.
    fn launch_fw(&self, _boot_params: &BootParams<'_>, _vtom: u64) -> Result<(), SvsmError> {
        Ok(())
    }

    /// Completes initialization of a per-CPU object during construction.
    fn setup_percpu(&self, cpu: &PerCpu) -> Result<(), SvsmError>;

    /// Completes initialization of a per-CPU object on the target CPU.
    fn setup_percpu_current(&self, cpu: &PerCpu) -> Result<(), SvsmError>;

    /// Determines the paging encryption masks for the current architecture.
    fn get_page_encryption_masks(&self) -> PageEncryptionMasks;

    /// Determine whether shadow stacks are supported.
    fn determine_cet_support(&self) -> bool {
        determine_cet_support_from_cpuid()
    }

    /// Get the features and the capabilities of the platform.
    fn capabilities(&self) -> Caps;

    /// Enable platform-specific Hyper-V hypercall operations.
    fn setup_hyperv_hypercalls(&self) -> Result<(), SvsmError> {
        Ok(())
    }

    /// Perform a hypercall.
    /// # Safety
    /// Hypercalls may have side-effects that affect the integrity of the
    /// system, and the caller must take responsibility for ensuring that the
    /// hypercall operation is safe.
    unsafe fn hypercall(
        &self,
        input_control: hyperv::HvHypercallInput,
        hypercall_pages: &hyperv::HypercallPagesGuard<'_>,
    ) -> hyperv::HvHypercallOutput;

    /// Obtain CPUID using platform-specific tables.
    fn cpuid(&self, eax: u32, ecx: u32) -> Option<CpuidResult>;

    /// Write a host-owned MSR.
    /// # Safety
    /// The caller must ensure that the requested MSR modification does mot
    /// affect memory safety.
    unsafe fn write_host_msr(&self, msr: u32, value: u64);

    /// Establishes state required for guest/host communication.
    fn setup_guest_host_comm(&mut self, _cpu: &PerCpu, _is_bsp: bool) {}

    /// Obtains a reference to an I/O port implemetation appropriate to the
    /// platform.
    fn get_io_port(&self) -> &'static dyn IOPort;

    /// Validates low memory below the specified physical address, with the
    /// exception of addresses reserved for use by the platform object which
    /// may pre-validated.  Intended only for use during early boot.
    /// # Safety
    /// The caller is required to ensure that it is safe to validate low
    /// memory.
    unsafe fn validate_low_memory(&self, addr: u64) -> Result<(), SvsmError> {
        // SAFETY: the caller takes responsibility for the safety of the
        // validation operation.
        unsafe {
            self.validate_virtual_page_range(
                MemoryRegion::new(VirtAddr::from(0u64), addr as usize),
                PageValidateOp::Validate,
            )
        }
    }

    /// Performs a page state change between private and shared states.
    fn page_state_change(
        &self,
        region: MemoryRegion<PhysAddr>,
        op: PageStateChangeOp,
    ) -> Result<(), SvsmError>;

    /// Marks a physical range of pages as valid or invalid for use as private
    /// pages.  Not usable in stage2.
    ///
    /// # Safety
    ///
    /// See the safety considerations for [SvsmPlatform::validate_virtual_page_range].
    unsafe fn validate_physical_page_range(
        &self,
        region: MemoryRegion<PhysAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError>;

    /// Marks a virtual range of pages as valid or invalid for use as private
    /// pages.  Provided primarily for use in stage2 where validation by
    /// physical address cannot be supported.
    /// # Safety
    /// The caller is required to ensure the safety of the validation operation
    /// on this memory range.
    unsafe fn validate_virtual_page_range(
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

    /// Determines whether a given interrupt vector was invoked as an external
    /// interrupt.
    fn is_external_interrupt(&self, vector: usize) -> bool;

    /// Start an additional processor.
    fn start_cpu(
        &self,
        cpu: &PerCpu,
        start_rip: u64,
        transition_page_table: &TransitionPageTable,
    ) -> Result<(), SvsmError>;

    /// Indicates whether this platform should invoke the SVSM request loop.
    fn start_svsm_request_loop(&self) -> bool {
        false
    }

    /// Perfrom a write to a memory-mapped IO area
    ///
    /// # Safety
    ///
    /// Caller must ensure that `vaddr` points to a properly aligned memory location and the
    /// memory accessed is part of a valid MMIO range.
    unsafe fn mmio_write(&self, vaddr: VirtAddr, data: &[u8]) -> Result<(), SvsmError>;

    /// Perfrom a read from a memory-mapped IO area
    ///
    /// # Safety
    ///
    /// Caller must ensure that `vaddr` points to a properly aligned memory location and the
    /// memory accessed is part of a valid MMIO range.
    unsafe fn mmio_read(
        &self,
        vaddr: VirtAddr,
        data: &mut [MaybeUninit<u8>],
    ) -> Result<(), SvsmError>;

    /// Terminates the guest.
    fn terminate() -> !
    where
        Self: Sized;
}

//FIXME - remove Copy trait
#[derive(Clone, Copy, Debug)]
pub enum SvsmPlatformCell {
    Snp(SnpPlatform),
    Tdp(TdpPlatform),
    Native(NativePlatform),
}

impl SvsmPlatformCell {
    pub fn new(suppress_svsm_interrupts: bool) -> Self {
        match *SVSM_PLATFORM_TYPE {
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

    pub fn global_init(self) {
        SVSM_PLATFORM_CELL
            .init(self)
            .expect("Failed to initialize SVSM platform cell");
        SVSM_PLATFORM
            .init(SVSM_PLATFORM_CELL.platform())
            .expect("Failed to initialize SVSM platform");
    }

    pub fn platform(&self) -> &dyn SvsmPlatform {
        match self {
            SvsmPlatformCell::Native(platform) => platform,
            SvsmPlatformCell::Snp(platform) => platform,
            SvsmPlatformCell::Tdp(platform) => platform,
        }
    }

    pub fn platform_mut(&mut self) -> &mut dyn SvsmPlatform {
        match self {
            SvsmPlatformCell::Native(platform) => platform,
            SvsmPlatformCell::Snp(platform) => platform,
            SvsmPlatformCell::Tdp(platform) => platform,
        }
    }

    pub fn platform_type(&self) -> SvsmPlatformType {
        match self {
            SvsmPlatformCell::Native(_) => SvsmPlatformType::Native,
            SvsmPlatformCell::Snp(_) => SvsmPlatformType::Snp,
            SvsmPlatformCell::Tdp(_) => SvsmPlatformType::Tdp,
        }
    }
}

/// This defines a platform abstraction to permit stage2 to run on different
/// underlying architectures.  It includes only functionality that is used
/// only in stage2.
pub trait Stage2Platform {
    /// Obtains the virtual address of the CPUID page, if any.
    fn get_cpuid_page(&self, _launch_info: &Stage2LaunchInfo) -> Option<VirtAddr> {
        None
    }
}

#[derive(Debug)]
pub enum Stage2PlatformCell {
    Snp(SnpStage2Platform),
    Tdp(TdpStage2Platform),
    Native(NativeStage2Platform),
}

impl Stage2PlatformCell {
    pub fn new(platform_type: SvsmPlatformType) -> Self {
        match platform_type {
            SvsmPlatformType::Native => Stage2PlatformCell::Native(NativeStage2Platform::new()),
            SvsmPlatformType::Snp => Stage2PlatformCell::Snp(SnpStage2Platform::new()),
            SvsmPlatformType::Tdp => Stage2PlatformCell::Tdp(TdpStage2Platform::new()),
        }
    }

    pub fn platform(&self) -> &dyn Stage2Platform {
        match self {
            Stage2PlatformCell::Native(platform) => platform,
            Stage2PlatformCell::Snp(platform) => platform,
            Stage2PlatformCell::Tdp(platform) => platform,
        }
    }
}

pub fn init_platform_type(platform_type: SvsmPlatformType) {
    SVSM_PLATFORM_TYPE.init(platform_type).unwrap();
}

pub fn init_capabilities() {
    let caps = SVSM_PLATFORM.capabilities();
    CAPS.init(caps).unwrap();
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

/// Terminates the guest with a platform-specific mechanism
pub fn terminate() -> ! {
    match *SVSM_PLATFORM_TYPE {
        SvsmPlatformType::Native => NativePlatform::terminate(),
        SvsmPlatformType::Snp => SnpPlatform::terminate(),
        SvsmPlatformType::Tdp => TdpPlatform::terminate(),
    }
}
