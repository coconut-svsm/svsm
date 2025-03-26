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
use crate::cpu::apic::{ApicIcr, IcrMessageType};
use crate::cpu::control_regs::read_cr3;
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::percpu::PerCpu;
use crate::cpu::smp::create_ap_start_context;
use crate::cpu::x86::apic::{x2apic_enable, x2apic_eoi, x2apic_icr_write};
use crate::error::SvsmError;
use crate::hyperv::{hyperv_setup_hypercalls, hyperv_start_cpu, is_hyperv_hypervisor};
use crate::io::{IOPort, DEFAULT_IO_DRIVER};
use crate::mm::PerCPUPageMappingGuard;
use crate::types::{PageSize, PAGE_SIZE};
use crate::utils::MemoryRegion;
use syscall::GlobalFeatureFlags;

use bootlib::kernel_launch::{ApStartContext, SIPI_STUB_GPA};
use core::{mem, ptr};

#[cfg(debug_assertions)]
use crate::mm::virt_to_phys;

#[cfg(test)]
use bootlib::platform::SvsmPlatformType;

#[derive(Clone, Copy, Debug)]
pub struct NativePlatform {
    is_hyperv: bool,
    transition_cr3: u32,
}

impl NativePlatform {
    pub fn new(_suppress_svsm_interrupts: bool) -> Self {
        // Execution is not possible unless X2APIC is supported.
        let features = CpuidResult::get(1, 0);
        if (features.ecx & 0x200000) == 0 {
            panic!("X2APIC is not supported");
        }
        Self {
            is_hyperv: is_hyperv_hypervisor(),
            transition_cr3: u64::from(read_cr3()).try_into().unwrap(),
        }
    }
}

impl SvsmPlatform for NativePlatform {
    #[cfg(test)]
    fn platform_type(&self) -> SvsmPlatformType {
        SvsmPlatformType::Native
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
        x2apic_enable();
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
        x2apic_icr_write(icr);
        Ok(())
    }

    fn eoi(&self) {
        x2apic_eoi();
    }

    fn is_external_interrupt(&self, _vector: usize) -> bool {
        // For a native platform, the hypervisor is fully trusted with all
        // event delivery, so all events are assumed not to be external
        // interrupts.
        false
    }

    fn start_cpu(&self, cpu: &PerCpu, start_rip: u64) -> Result<(), SvsmError> {
        let context = cpu.get_initial_context(start_rip);
        if self.is_hyperv {
            return hyperv_start_cpu(cpu, &context);
        }

        // Translate this context into an AP start context and place it it in
        // the AP startup transition page.
        let ap_context = create_ap_start_context(&context, self.transition_cr3);

        let context_pa = PhysAddr::new(SIPI_STUB_GPA as usize);
        let context_mapping = PerCPUPageMappingGuard::create_4k(context_pa)?;

        // SAFETY: the address of the transition page was made valid when the
        // `PerCPUPageMappingGuard` was created.
        unsafe {
            let size = mem::size_of::<ApStartContext>();
            let context_va = context_mapping.virt_addr() + PAGE_SIZE - size;
            let context_ptr = context_va.as_mut_ptr::<ApStartContext>();
            ptr::copy_nonoverlapping(&ap_context, context_ptr, 1);
        }

        // Now that the AP startup transition page has been configured, send
        // INIT-SIPI to start the processor.  No second SIPI is required when
        // running virtualized.
        let icr = ApicIcr::new().with_destination(cpu.shared().apic_id());
        let init_icr = icr.with_message_type(IcrMessageType::Init);
        self.post_irq(init_icr.into())?;
        let sipi_vector = SIPI_STUB_GPA >> 12;
        let sipi_icr = icr
            .with_message_type(IcrMessageType::Sipi)
            .with_vector(sipi_vector.try_into().unwrap());
        self.post_irq(sipi_icr.into())?;

        Ok(())
    }
}
