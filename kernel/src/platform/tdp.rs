// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 Intel Corporation
//
// Author: Peter Fang <peter.fang@intel.com>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::console::init_svsm_console;
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::msr::read_msr;
use crate::cpu::percpu::PerCpu;
use crate::cpu::smp::create_ap_start_context;
use crate::cpu::x86::apic::{apic_register_bit, APIC_MSR_ISR};
use crate::error::SvsmError;
use crate::hyperv;
use crate::io::IOPort;
use crate::mm::PerCPUPageMappingGuard;
use crate::platform::{PageEncryptionMasks, PageStateChangeOp, PageValidateOp, SvsmPlatform};
use crate::tdx::tdcall::{
    td_accept_physical_memory, td_accept_virtual_memory, tdvmcall_halt, tdvmcall_io_read,
    tdvmcall_io_write,
};
use crate::tdx::TdxError;
use crate::types::{PageSize, PAGE_SIZE};
use crate::utils::immut_after_init::ImmutAfterInitCell;
use crate::utils::{is_aligned, MemoryRegion};
use bootlib::kernel_launch::{ApStartContext, SIPI_STUB_GPA};
use core::{mem, ptr};

#[cfg(test)]
use bootlib::platform::SvsmPlatformType;

static GHCI_IO_DRIVER: GHCIIOPort = GHCIIOPort::new();
static VTOM: ImmutAfterInitCell<usize> = ImmutAfterInitCell::uninit();

#[derive(Debug)]
#[repr(C, packed)]
pub struct TdMailbox {
    pub vcpu_index: u32,
}

// Both structures must fit in a page
const _: () = assert!(mem::size_of::<TdMailbox>() + mem::size_of::<ApStartContext>() <= PAGE_SIZE);

// SAFETY: caller must ensure `mailbox` points to a valid memory address.
unsafe fn wakeup_ap(mailbox: *mut TdMailbox, index: usize) {
    // SAFETY: caller must ensure the address is valid and not aliased.
    unsafe {
        // PerCpu's CPU index has a direct mapping to TD vCPU index
        (*mailbox).vcpu_index = index.try_into().expect("CPU index too large");
    }
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
        tdvmcall_halt();
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
        Err(TdxError::Unimplemented.into())
    }

    fn validate_physical_page_range(
        &self,
        region: MemoryRegion<PhysAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        // The cast to u32 below is awkward, but the is_aligned() function
        // requires its type to be convertible to u32 - which usize is not -
        // and for an alignment check, only the low 32 bits are needed anyway
        if !region.start().is_aligned(PAGE_SIZE)
            || !is_aligned(region.len() as u32, PAGE_SIZE as u32)
        {
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

    fn validate_virtual_page_range(
        &self,
        region: MemoryRegion<VirtAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        // The cast to u32 below is awkward, but the is_aligned() function
        // requires its type to be convertible to u32 - which usize is not -
        // and for an alignment check, only the low 32 bits are needed anyway
        if !region.start().is_aligned(PAGE_SIZE)
            || !is_aligned(region.len() as u32, PAGE_SIZE as u32)
        {
            return Err(SvsmError::InvalidAddress);
        }
        match op {
            // SAFETY: safety work on the address is yet to be completed.
            PageValidateOp::Validate => unsafe {
                // TODO - verify safety of the physical address range.
                td_accept_virtual_memory(region)
            },
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

    fn post_irq(&self, _icr: u64) -> Result<(), SvsmError> {
        Err(TdxError::Unimplemented.into())
    }

    fn eoi(&self) {}

    fn is_external_interrupt(&self, vector: usize) -> bool {
        // Examine the APIC ISR to determine whether this interrupt vector is
        // active.  If so, it is assumed to be an external interrupt.
        let (msr, mask) = apic_register_bit(vector);
        (read_msr(APIC_MSR_ISR + msr) & mask as u64) != 0
    }

    fn start_cpu(
        &self,
        cpu: &PerCpu,
        context: &hyperv::HvInitialVpContext,
    ) -> Result<(), SvsmError> {
        // Translate this context into an AP start context and place it in the
        // AP startup transition page.
        //
        // transition_cr3 is not needed since all TD APs are using the stage2
        // page table set up by the BSP.
        let ap_context = create_ap_start_context(context, 0);

        // The mailbox page was already accepted by the BSP in stage2 and
        // therefore it's been initialized as a zero page.
        let context_pa = PhysAddr::new(SIPI_STUB_GPA as usize);
        let context_mapping = PerCPUPageMappingGuard::create_4k(context_pa)?;

        // SAFETY: the address of the mailbox page was made valid when the
        // `PerCPUPageMappingGuard` was created.
        unsafe {
            let mbx_va = context_mapping.virt_addr();
            let size = mem::size_of::<ApStartContext>();
            let context_ptr = (mbx_va + PAGE_SIZE - size).as_mut_ptr::<ApStartContext>();
            ptr::copy_nonoverlapping(&ap_context, context_ptr, 1);
            wakeup_ap(mbx_va.as_mut_ptr::<TdMailbox>(), cpu.shared().cpu_index());
        }
        Ok(())
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
