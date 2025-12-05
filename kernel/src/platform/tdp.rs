// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 Intel Corporation
//
// Author: Peter Fang <peter.fang@intel.com>

use super::capabilities::Caps;
use super::{PageEncryptionMasks, PageStateChangeOp, PageValidateOp, Stage2Platform, SvsmPlatform};
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::console::init_svsm_console;
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::percpu::PerCpu;
use crate::cpu::smp::create_ap_start_context;
use crate::cpu::x86::{apic_in_service, apic_initialize, apic_sw_enable};
use crate::cpu::IrqGuard;
use crate::error::SvsmError;
use crate::hyperv;
use crate::hyperv::{hyperv_start_cpu, IS_HYPERV};
use crate::io::IOPort;
use crate::mm::PerCPUMapping;
use crate::tdx::apic::TDX_APIC_ACCESSOR;
use crate::tdx::tdcall::{
    td_accept_physical_memory, td_accept_virtual_memory, tdcall_vm_read, tdvmcall_halt,
    tdvmcall_hyperv_hypercall, tdvmcall_io_read, tdvmcall_io_write, tdvmcall_map_gpa,
    tdvmcall_wrmsr, TdpHaltInterruptState, MD_TDCS_NUM_L2_VMS,
};
use crate::types::{PageSize, PAGE_SIZE};
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::{is_aligned, MemoryRegion};
use bootlib::kernel_launch::{ApStartContext, SIPI_STUB_GPA};
use core::mem;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, Ordering};
use syscall::GlobalFeatureFlags;
use zerocopy::FromBytes;

#[cfg(test)]
use bootlib::platform::SvsmPlatformType;

static GHCI_IO_DRIVER: GHCIIOPort = GHCIIOPort::new();
static VTOM: ImmutAfterInitCell<usize> = ImmutAfterInitCell::uninit();

#[derive(Debug, FromBytes)]
#[repr(C)]
pub struct TdMailbox {
    pub vcpu_index: AtomicU32,
}

// Both structures must fit in a page
const _: () = assert!(mem::size_of::<TdMailbox>() + mem::size_of::<ApStartContext>() <= PAGE_SIZE);

fn wakeup_ap(mailbox: &TdMailbox, cpu_index: usize) {
    // PerCpu's CPU index has a direct mapping to TD vCPU index
    mailbox
        .vcpu_index
        .store(cpu_index.try_into().unwrap(), Ordering::Release);
}

#[derive(Clone, Copy, Debug)]
pub struct TdpPlatform {}

impl TdpPlatform {
    pub fn new(_suppress_svsm_interrupts: bool) -> Self {
        Self {}
    }
}

impl SvsmPlatform for TdpPlatform {
    #[cfg(test)]
    fn platform_type(&self) -> SvsmPlatformType {
        SvsmPlatformType::Tdp
    }

    fn halt() {
        tdvmcall_halt(TdpHaltInterruptState::Disabled);
    }

    fn idle_halt(&self, _irq_guard: &IrqGuard) {
        tdvmcall_halt(TdpHaltInterruptState::Enabled);
    }

    fn env_setup(&mut self, debug_serial_port: u16, vtom: usize) -> Result<(), SvsmError> {
        assert_ne!(vtom, 0);
        VTOM.init(vtom).map_err(|_| SvsmError::PlatformInit)?;
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
        Ok(())
    }

    fn setup_percpu_current(&self, _cpu: &PerCpu) -> Result<(), SvsmError> {
        apic_initialize(&TDX_APIC_ACCESSOR);
        // apic_enable() is not needed as both KVM and Hyper-V hosts initialize
        // TD APICs with (APIC_ENABLE_MASK | APIC_X2_ENABLE_MASK)
        apic_sw_enable();
        Ok(())
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

    fn capabilities(&self) -> Caps {
        let num_vms = tdcall_vm_read(MD_TDCS_NUM_L2_VMS);
        // VM 0 is always L1 itself
        let vm_bitmap = ((1 << num_vms) - 1) << 1;
        let features = GlobalFeatureFlags::PLATFORM_TYPE_TDP;
        Caps::new(vm_bitmap, features)
    }

    /// # Safety
    /// Hypercalls may have side-effects that affect the integrity of the
    /// system, and the caller must take responsibility for ensuring that the
    /// hypercall operation is safe.
    unsafe fn hypercall(
        &self,
        input_control: hyperv::HvHypercallInput,
        hypercall_pages: &hyperv::HypercallPagesGuard<'_>,
    ) -> hyperv::HvHypercallOutput {
        hyperv::execute_host_hypercall(input_control, hypercall_pages, |registers| {
            tdvmcall_hyperv_hypercall(registers);
        })
    }

    fn cpuid(&self, eax: u32, ecx: u32) -> Option<CpuidResult> {
        Some(CpuidResult::get(eax, ecx))
    }

    unsafe fn write_host_msr(&self, msr: u32, value: u64) {
        tdvmcall_wrmsr(msr, value);
    }

    fn get_io_port(&self) -> &'static dyn IOPort {
        &GHCI_IO_DRIVER
    }

    fn page_state_change(
        &self,
        region: MemoryRegion<PhysAddr>,
        _size: PageSize,
        op: PageStateChangeOp,
    ) -> Result<(), SvsmError> {
        if !region.start().is_aligned(PAGE_SIZE) || !is_aligned(region.len(), PAGE_SIZE) {
            return Err(SvsmError::InvalidAddress);
        }
        let gpa = match op {
            PageStateChangeOp::Private => u64::from(region.start()),
            PageStateChangeOp::Shared => u64::from(region.start()) | *VTOM as u64,
            _ => return Err(SvsmError::NotSupported),
        };

        tdvmcall_map_gpa(gpa, region.len() as u64)?;

        Ok(())
    }

    fn validate_physical_page_range(
        &self,
        region: MemoryRegion<PhysAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        if !region.start().is_aligned(PAGE_SIZE) || !is_aligned(region.len(), PAGE_SIZE) {
            return Err(SvsmError::InvalidAddress);
        }
        match op {
            // SAFETY: safety work on the address is yet to be completed.
            PageValidateOp::Validate => unsafe {
                // TODO - verify safety of the physical address range.
                td_accept_physical_memory(region)
            },
            PageValidateOp::Invalidate => {
                // No work is required at invalidation time.
                Ok(())
            }
        }
    }

    /// # Safety
    /// The caller is required to ensure the safety of the validation operation
    /// on this memory range.
    unsafe fn validate_virtual_page_range(
        &self,
        region: MemoryRegion<VirtAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        if !region.start().is_aligned(PAGE_SIZE) || !is_aligned(region.len(), PAGE_SIZE) {
            return Err(SvsmError::InvalidAddress);
        }
        match op {
            // SAFETY: The caller is required to ensure the safety of the
            // memory range.
            PageValidateOp::Validate => unsafe { td_accept_virtual_memory(region) },
            PageValidateOp::Invalidate => Ok(()),
        }
    }

    fn configure_alternate_injection(&mut self, alt_inj_requested: bool) -> Result<(), SvsmError> {
        if alt_inj_requested {
            Err(SvsmError::NotSupported)
        } else {
            Ok(())
        }
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

    fn is_external_interrupt(&self, vector: usize) -> bool {
        apic_in_service(vector)
    }

    fn start_cpu(&self, cpu: &PerCpu, start_rip: u64) -> Result<(), SvsmError> {
        // Translate this context into an AP start context and place it in the
        // AP startup transition page.
        let mut context = cpu.get_initial_context(start_rip);

        // Set the initial EFER to zero so that it is not reloaded.  This
        // is necessary since the TDX module does not permit changes to EFER
        // when running in the L1.
        context.efer = 0;

        // The mailbox page was already accepted by the BSP in stage2 and
        // therefore it's been initialized as a zero page.
        let context_pa = SIPI_STUB_GPA as usize + PAGE_SIZE - mem::size_of::<ApStartContext>();
        // SAFETY: the physical address is known to point to the location where
        // the start context is to be created.
        let mut context_mapping = unsafe {
            PerCPUMapping::<MaybeUninit<ApStartContext>>::create(PhysAddr::new(context_pa))?
        };

        // transition_cr3 is not needed since all TD APs are using the stage2
        // page table set up by the BSP.
        context_mapping.write(create_ap_start_context(&context, 0));

        // When running under Hyper-V, the target vCPU does not begin running
        // until a start hypercall is issued, so make that hypercall now.
        if *IS_HYPERV {
            // Do not expose the actual CPU context via the hypercall since it
            // is not needed.  Use a default context instead.
            let ctx = hyperv::HvInitialVpContext::default();
            hyperv_start_cpu(cpu, &ctx)?;
        }

        drop(context_mapping);

        // The wakeup mailbox lives at the base of the context page.  While it
        // would be possible to borrow the same per-CPU page mapping as the
        // context page, this involves unsafe operations, and creating a
        // separate mapping is entirely safe.  The optimization of reusing
        // the existing mapping is not significant enough to be worth the use
        // of unsafe code.
        // SAFETY: the physical address is known to point to a mailbox
        // structure.
        let mailbox =
            unsafe { PerCPUMapping::<TdMailbox>::create(PhysAddr::from(SIPI_STUB_GPA as usize))? };
        wakeup_ap(mailbox.as_ref(), cpu.get_cpu_index());

        Ok(())
    }

    unsafe fn mmio_write(&self, _vaddr: VirtAddr, _data: &[u8]) -> Result<(), SvsmError> {
        unimplemented!()
    }

    unsafe fn mmio_read(
        &self,
        _vaddr: VirtAddr,
        _data: &mut [MaybeUninit<u8>],
    ) -> Result<(), SvsmError> {
        unimplemented!()
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
        tdvmcall_io_write(port, value);
    }

    fn inb(&self, port: u16) -> u8 {
        tdvmcall_io_read::<u8>(port) as u8
    }

    fn outw(&self, port: u16, value: u16) {
        tdvmcall_io_write(port, value);
    }

    fn inw(&self, port: u16) -> u16 {
        tdvmcall_io_read::<u16>(port) as u16
    }

    fn outl(&self, port: u16, value: u32) {
        tdvmcall_io_write(port, value);
    }

    fn inl(&self, port: u16) -> u32 {
        tdvmcall_io_read::<u32>(port)
    }
}

#[derive(Default, Debug)]
pub struct TdpStage2Platform {}

impl TdpStage2Platform {
    pub fn new() -> Self {
        Self {}
    }
}

impl Stage2Platform for TdpStage2Platform {}
