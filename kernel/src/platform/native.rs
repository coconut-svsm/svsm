// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
// Copyright (c) SUSE LLC
//
// Author: Jon Lange <jlange@microsoft.com>
// Author: Joerg Roedel <jroedel@suse.de>

use super::capabilities::Caps;
use super::{PageEncryptionMasks, PageStateChangeOp, PageValidateOp, SvsmPlatform};
use crate::address::{PhysAddr, VirtAddr};
use crate::console::init_svsm_console;
use crate::cpu::IrqGuard;
use crate::cpu::apic::{ApicIcr, IcrMessageType};
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::irq_state::raw_irqs_disable;
use crate::cpu::msr::write_msr;
use crate::cpu::percpu::PerCpu;
use crate::cpu::smp::create_ap_start_context;
use crate::cpu::x86::{
    X2APIC_ACCESSOR, apic_enable, apic_initialize, apic_post_irq, apic_sw_enable,
};
use crate::error::SvsmError;
use crate::hyperv;
use crate::hyperv::IS_HYPERV;
use crate::hyperv::hyperv_start_cpu;
use crate::io::{DEFAULT_IO_DRIVER, IOPort};
use crate::mm::PerCPUMapping;
use crate::mm::TransitionPageTable;
use crate::types::PAGE_SIZE;
#[cfg(debug_assertions)]
use crate::types::PageSize;
use crate::utils::MemoryRegion;

use bootdefs::kernel_launch::ApStartContext;
use bootdefs::kernel_launch::SIPI_STUB_GPA;
use core::arch::asm;
use core::mem;
use core::mem::MaybeUninit;
use syscall::GlobalFeatureFlags;

#[cfg(debug_assertions)]
use crate::mm::virt_to_phys;

#[cfg(test)]
use bootdefs::platform::SvsmPlatformType;

#[derive(Clone, Copy, Debug)]
pub struct NativePlatform {}

impl NativePlatform {
    pub fn new(_suppress_svsm_interrupts: bool) -> Self {
        // Execution is not possible unless X2APIC is supported.
        let features = CpuidResult::get(1, 0);
        if (features.ecx & 0x200000) == 0 {
            panic!("X2APIC is not supported");
        }
        Self {}
    }
}

impl SvsmPlatform for NativePlatform {
    #[cfg(test)]
    fn platform_type(&self) -> SvsmPlatformType {
        SvsmPlatformType::Native
    }

    fn idle_halt(&self, _guard: &IrqGuard) {
        // SAFETY: executing HLT in assembly is always safe.
        unsafe {
            asm!("sti", "hlt", "cli");
        }
    }

    fn env_setup(&mut self, debug_serial_port: u16, _vtom: usize) -> Result<(), SvsmError> {
        // In the native platform, console output does not require the use of
        // any platform services, so it can be initialized immediately.
        init_svsm_console(&DEFAULT_IO_DRIVER, debug_serial_port)
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
        apic_initialize(&X2APIC_ACCESSOR);
        apic_enable();
        apic_sw_enable();
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

    fn capabilities(&self) -> Caps {
        let features = GlobalFeatureFlags::PLATFORM_TYPE_NATIVE;
        Caps::new(0, features)
    }

    fn setup_hyperv_hypercalls(&self) -> Result<(), SvsmError> {
        hyperv::setup_hypercall_page()
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
        // SAFETY: the caller guarantees the safety of the hypercall
        // parameters.
        unsafe { hyperv::execute_hypercall(input_control, hypercall_pages) }
    }

    fn cpuid(&self, eax: u32, ecx: u32) -> Option<CpuidResult> {
        Some(CpuidResult::get(eax, ecx))
    }

    unsafe fn write_host_msr(&self, msr: u32, value: u64) {
        // SAFETY: the caller takes responsibility for ensuring the safety
        // of the MSR write.
        unsafe {
            write_msr(msr, value);
        }
    }

    fn get_io_port(&self) -> &'static dyn IOPort {
        &DEFAULT_IO_DRIVER
    }

    unsafe fn validate_low_memory(&self, _addr: u64, _vaddr_valid: bool) -> Result<(), SvsmError> {
        Ok(())
    }

    fn page_state_change(
        &self,
        _region: MemoryRegion<PhysAddr>,
        _op: PageStateChangeOp,
    ) -> Result<(), SvsmError> {
        Ok(())
    }

    unsafe fn validate_physical_page_range(
        &self,
        _region: MemoryRegion<PhysAddr>,
        _op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        Ok(())
    }

    /// # Safety
    /// The caller is required to ensure the safety of the validation operation
    /// on this memory range.
    unsafe fn validate_virtual_page_range(
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

    fn is_external_interrupt(&self, _vector: usize) -> bool {
        // For a native platform, the hypervisor is fully trusted with all
        // event delivery, so all events are assumed not to be external
        // interrupts.
        false
    }

    fn start_cpu(
        &self,
        cpu: &PerCpu,
        start_rip: u64,
        transition_page_table: &TransitionPageTable,
    ) -> Result<(), SvsmError> {
        let context = cpu.get_initial_context(start_rip);
        if *IS_HYPERV {
            return hyperv_start_cpu(cpu, &context);
        }

        // Translate this context into an AP start context and place it it in
        // the AP startup transition page.

        let context_pa = SIPI_STUB_GPA as usize + PAGE_SIZE - mem::size_of::<ApStartContext>();
        // SAFETY: the physical address is known to point to the location where
        // the start context is to be created.
        let mut context_mapping = unsafe {
            PerCPUMapping::<MaybeUninit<ApStartContext>>::create(PhysAddr::new(context_pa))?
        };
        context_mapping.write(create_ap_start_context(&context, transition_page_table));

        // Now that the AP startup transition page has been configured, send
        // INIT-SIPI to start the processor.  No second SIPI is required when
        // running virtualized.
        let icr = ApicIcr::new().with_destination(cpu.shared().apic_id());
        let init_icr = icr.with_message_type(IcrMessageType::Init);
        apic_post_irq(init_icr.into());
        let sipi_vector = SIPI_STUB_GPA >> 12;
        let sipi_icr = icr
            .with_message_type(IcrMessageType::Sipi)
            .with_vector(sipi_vector.try_into().unwrap());
        apic_post_irq(sipi_icr.into());

        Ok(())
    }

    /// Perform a write to a memory-mapped IO area
    ///
    /// This function expects data to be 1, 2, 4 or 8 bytes long.
    ///
    /// It is not possible to loop and write one byte at a time because mmio devices (e.g., those emulated by QEMU)
    /// expect certain registers to be written with a single operation. Using a generic on SvsmPlatform is
    /// not possible because it uses the dyn trait.
    ///
    /// # Safety
    ///
    /// Caller must ensure that `vaddr` points to a properly aligned memory location and the
    /// memory accessed is part of a valid MMIO range.
    unsafe fn mmio_write(&self, vaddr: VirtAddr, data: &[u8]) -> Result<(), SvsmError> {
        match data.len() {
            1 => {
                // SAFETY: We are trusting the caller to ensure validity of `vaddr`.
                unsafe {
                    mmio_write_type::<u8>(vaddr, data);
                }
            }
            2 => {
                // SAFETY: We are trusting the caller to ensure validity of `vaddr`.
                unsafe {
                    mmio_write_type::<u16>(vaddr, data);
                }
            }
            4 => {
                // SAFETY: We are trusting the caller to ensure validity of `vaddr`.
                unsafe {
                    mmio_write_type::<u32>(vaddr, data);
                }
            }
            8 => {
                // SAFETY: We are trusting the caller to ensure validity of `vaddr`.
                unsafe {
                    mmio_write_type::<u64>(vaddr, data);
                }
            }
            _ => return Err(SvsmError::InvalidBytes),
        };

        Ok(())
    }

    /// Perform a read from a memory-mapped IO area
    ///
    /// This function expects reads to be 1, 2, 4 or 8 bytes long.
    ///
    /// It is not possible to loop and read one byte at a time because mmio devices (e.g., those emulated by QEMU)
    /// expect certain registers to be read with a single operation. Using a generic on SvsmPlatform is
    /// not possible because it uses the dyn trait.
    ///
    /// # Safety
    ///
    /// Caller must ensure that `vaddr` points to a properly aligned memory location and the
    /// memory accessed is part of a valid MMIO range.
    unsafe fn mmio_read(
        &self,
        vaddr: VirtAddr,
        data: &mut [MaybeUninit<u8>],
    ) -> Result<(), SvsmError> {
        match data.len() {
            1 => {
                // SAFETY: We are trusting the caller to ensure validity of `vaddr`.
                unsafe {
                    mmio_read_type::<u8>(vaddr, data);
                }
            }
            2 => {
                // SAFETY: We are trusting the caller to ensure validity of `vaddr`.
                unsafe {
                    mmio_read_type::<u16>(vaddr, data);
                }
            }
            4 => {
                // SAFETY: We are trusting the caller to ensure validity of `vaddr`.
                unsafe {
                    mmio_read_type::<u32>(vaddr, data);
                }
            }
            8 => {
                // SAFETY: We are trusting the caller to ensure validity of `vaddr`.
                unsafe {
                    mmio_read_type::<u64>(vaddr, data);
                }
            }
            _ => return Err(SvsmError::InvalidBytes),
        };

        Ok(())
    }

    fn terminate() -> !
    where
        Self: Sized,
    {
        raw_irqs_disable();
        loop {
            Self::halt();
        }
    }
}

unsafe fn mmio_write_type<T: Copy>(vaddr: VirtAddr, data: &[u8]) {
    let data_ptr = data.as_ptr().cast::<T>();
    let ptr = vaddr.as_mut_ptr::<T>();

    // SAFETY: We are trusting the caller to ensure validity of `vaddr`.
    unsafe {
        if data_ptr.is_aligned() {
            ptr.write_volatile(data_ptr.read());
        } else {
            ptr.write_volatile(data_ptr.read_unaligned());
        }
    };
}

unsafe fn mmio_read_type<T>(vaddr: VirtAddr, data: &mut [MaybeUninit<u8>]) {
    let data_ptr = data.as_mut_ptr().cast::<T>();
    let ptr = vaddr.as_mut_ptr::<T>();

    // SAFETY: We are trusting the caller to ensure validity of `vaddr`.
    unsafe {
        if data_ptr.is_aligned() {
            data_ptr.write(ptr.read_volatile());
        } else {
            data_ptr.write_unaligned(ptr.read_volatile());
        }
    };
}
