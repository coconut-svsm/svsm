// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use super::PageEncryptionMasks;
use super::PageStateChangeOp;
use super::PageValidateOp;
use super::PlatformPageType;
use super::Stage2Platform;
use super::SvsmPlatform;
use super::capabilities::Caps;
use super::snp_fw::{
    copy_tables_to_fw, launch_fw, prepare_fw_launch, print_fw_meta, validate_fw, validate_fw_memory,
};
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::boot_params::BootParams;
use crate::console::init_svsm_console;
use crate::cpu::cpuid::CpuidResult;
use crate::cpu::cpuid::cpuid_table;
use crate::cpu::cpuid::init_cpuid_table;
use crate::cpu::irq_state::raw_irqs_disable;
use crate::cpu::percpu::{PerCpu, current_ghcb, this_cpu};
use crate::cpu::tlb::TlbFlushScope;
use crate::cpu::x86::{apic_enable, apic_initialize, apic_sw_enable};
use crate::error::ApicError::Registration;
use crate::error::SvsmError;
use crate::greq::driver::guest_request_driver_init;
use crate::hyperv;
use crate::io::IOPort;
use crate::mm::PAGE_SIZE;
use crate::mm::PAGE_SIZE_2M;
use crate::mm::PerCPUPageMappingGuard;
use crate::mm::TransitionPageTable;
use crate::mm::memory::write_guest_memory_map;
use crate::platform::IrqGuard;
use crate::sev::ghcb::GHCBIOSize;
use crate::sev::hv_doorbell::HVDoorbell;
use crate::sev::msr_protocol::{
    GHCBHvFeatures, hypervisor_ghcb_features, request_termination_msr, verify_ghcb_version,
};
use crate::sev::secrets_page::initialize_secrets_page;
use crate::sev::status::vtom_enabled;
use crate::sev::tlb::flush_tlb_scope;
use crate::sev::{
    GHCB_APIC_ACCESSOR, PvalidateOp, init_hypervisor_ghcb_features, pvalidate_range,
    sev_status_init, sev_status_verify,
};
use crate::utils::MemoryRegion;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use syscall::GlobalFeatureFlags;

use bootdefs::kernel_launch::Stage2LaunchInfo;
#[cfg(test)]
use bootdefs::platform::SvsmPlatformType;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

static GHCB_IO_DRIVER: GHCBIOPort = GHCBIOPort::new();

static VTOM: ImmutAfterInitCell<usize> = ImmutAfterInitCell::uninit();

static APIC_EMULATION_REG_COUNT: AtomicU32 = AtomicU32::new(0);

/// # Safety
///
/// See the safety considerations for [`pvalidate_range()`].
unsafe fn pvalidate_page_range(
    range: MemoryRegion<PhysAddr>,
    op: PvalidateOp,
) -> Result<(), SvsmError> {
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
        // SAFETY: The mapping correctly represents the physical address range
        // and therefore is safe with respect to other memory operations.
        unsafe {
            pvalidate_range(MemoryRegion::new(mapping.virt_addr(), len), op)?;
        }
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
    pub fn new(suppress_svsm_interrupts: bool) -> Self {
        Self {
            can_use_interrupts: !suppress_svsm_interrupts,
        }
    }
}

unsafe extern "C" {
    fn snp_idle_halt(hv_doorbell: *const HVDoorbell);
}

impl SvsmPlatform for SnpPlatform {
    #[cfg(test)]
    fn platform_type(&self) -> SvsmPlatformType {
        SvsmPlatformType::Snp
    }

    fn idle_halt(&self, _guard: &IrqGuard) {
        let hv_doorbell = this_cpu().hv_doorbell();
        let ptr = match hv_doorbell {
            Some(doorbell) => ptr::from_ref(doorbell),
            None => ptr::null(),
        };
        // SAFETY: The correct #HV doorbell address was calculated above.
        unsafe {
            snp_idle_halt(ptr);
        }
    }

    fn env_setup(&mut self, _debug_serial_port: u16, vtom: usize) -> Result<(), SvsmError> {
        sev_status_init();
        VTOM.init(vtom).map_err(|_| SvsmError::PlatformInit)?;
        Ok(())
    }

    /// # Safety
    /// The caller must specify a valid virtual address for the specified type
    /// of page.
    unsafe fn initialize_platform_page(&self, page_type: PlatformPageType, vaddr: VirtAddr) {
        match page_type {
            PlatformPageType::Cpuid => {
                // SAFETY: the caller takes responsibility for the correctness
                // of the virtual address.
                unsafe {
                    init_cpuid_table(vaddr);
                }
            }
            PlatformPageType::Secrets => {
                // SAFETY: the caller takes responsibility for the correctness
                // of the virtual address.
                unsafe {
                    initialize_secrets_page(vaddr);
                }
            }
        }
    }

    fn env_setup_late(&mut self, debug_serial_port: u16) -> Result<(), SvsmError> {
        init_svsm_console(&GHCB_IO_DRIVER, debug_serial_port)?;
        sev_status_verify();
        init_hypervisor_ghcb_features()?;
        Ok(())
    }

    fn env_setup_svsm(&self) -> Result<(), SvsmError> {
        if hypervisor_ghcb_features().contains(GHCBHvFeatures::SEV_SNP_RESTR_INJ) {
            GHCB_APIC_ACCESSOR.set_use_restr_inj(true);
            this_cpu().setup_hv_doorbell()?;
        }
        guest_request_driver_init();
        Ok(())
    }

    /// # Safety
    /// The caller must specify a valid virtual address for the specified type
    /// of page.
    unsafe fn free_unused_platform_page(&self, _page_type: PlatformPageType, _vaddr: VirtAddr) {
        // All platform page types are used on SNP, so no platform pages should
        // be freed.
    }

    fn prepare_fw(
        &self,
        boot_params: &BootParams<'_>,
        kernel_region: MemoryRegion<PhysAddr>,
    ) -> Result<(), SvsmError> {
        if let Some(fw_meta) = &boot_params.get_fw_metadata() {
            print_fw_meta(fw_meta);
            validate_fw_memory(boot_params, fw_meta, &kernel_region)?;
            write_guest_memory_map(boot_params)?;
            // SAFETY: we've verified the firmware memory addresses above.
            // This is called from CPU 0, so the underlying physical address
            // is not being aliased.
            unsafe {
                copy_tables_to_fw(fw_meta, &kernel_region)?;
                validate_fw(boot_params)?;
            }
            prepare_fw_launch(fw_meta)?;
        }
        Ok(())
    }

    fn launch_fw(&self, boot_params: &BootParams<'_>, vtom: u64) -> Result<(), SvsmError> {
        if boot_params.should_launch_fw() {
            launch_fw(boot_params, vtom)
        } else {
            Ok(())
        }
    }

    fn setup_percpu(&self, cpu: &PerCpu) -> Result<(), SvsmError> {
        // Setup GHCB
        cpu.setup_ghcb()
    }

    fn setup_percpu_current(&self, cpu: &PerCpu) -> Result<(), SvsmError> {
        cpu.register_ghcb()?;

        if GHCB_APIC_ACCESSOR.use_restr_inj() {
            cpu.setup_hv_doorbell()?;
        }

        apic_initialize(&GHCB_APIC_ACCESSOR);
        apic_enable();
        apic_sw_enable();

        Ok(())
    }

    fn get_page_encryption_masks(&self) -> PageEncryptionMasks {
        // Find physical address size.
        let processor_capacity =
            cpuid_table(0x80000008, 0).expect("Can not get physical address size from CPUID table");
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
                cpuid_table(0x8000001f, 0).expect("Can not get C-Bit position from CPUID table");
            let c_bit = sev_capabilities.ebx & 0x3f;
            PageEncryptionMasks {
                private_pte_mask: 1 << c_bit,
                shared_pte_mask: 0,
                addr_mask_width: c_bit,
                phys_addr_sizes: processor_capacity.eax,
            }
        }
    }

    fn determine_cet_support(&self) -> bool {
        // Examine CPUID information to see whether CET is supported by the
        // hypervisor.  If no CPUID information is present, then assume that
        // CET is supported.
        if let Some(cpuid) = cpuid_table(7, 0) {
            (cpuid.ecx & 0x80) != 0
        } else {
            todo!()
        }
    }

    fn capabilities(&self) -> Caps {
        // VMPL0 is SVSM. VMPL1 to VMPL3 are guest.
        let vm_bitmap: u64 = 0xE;
        let features = GlobalFeatureFlags::PLATFORM_TYPE_SNP;
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
            current_ghcb()
                .vmmcall(registers)
                .expect("VMMCALL exit failed");
        })
    }

    fn cpuid(&self, eax: u32, ecx: u32) -> Option<CpuidResult> {
        // If this is an architectural CPUID leaf, then extract the result
        // from the CPUID table.  Otherwise, request the value from the
        // hypervisor.
        if (eax >> 28) == 4 {
            current_ghcb().cpuid(eax, ecx).ok()
        } else {
            cpuid_table(eax, ecx)
        }
    }

    unsafe fn write_host_msr(&self, msr: u32, value: u64) {
        current_ghcb()
            .wrmsr(msr, value)
            .expect("Host MSR access failed");
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

    /// The caller is required to ensure that it is safe to validate low
    /// memory.
    unsafe fn validate_low_memory(&self, addr: u64, vaddr_valid: bool) -> Result<(), SvsmError> {
        // SAFETY: the caller takes responsibility for the safety of the
        // validation operation.
        unsafe {
            if vaddr_valid {
                self.validate_virtual_page_range(
                    MemoryRegion::new(VirtAddr::from(0u64), addr as usize),
                    PageValidateOp::Validate,
                )
            } else {
                self.validate_physical_page_range(
                    MemoryRegion::new(PhysAddr::from(0u64), addr as usize),
                    PageValidateOp::Validate,
                )
            }
        }
    }

    /// Performs a page state change between private and shared states.
    fn page_state_change(
        &self,
        region: MemoryRegion<PhysAddr>,
        op: PageStateChangeOp,
    ) -> Result<(), SvsmError> {
        current_ghcb().page_state_change(region, op)
    }

    unsafe fn validate_physical_page_range(
        &self,
        region: MemoryRegion<PhysAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        // SAFETY: caller must uphold safety requirements
        unsafe { pvalidate_page_range(region, PvalidateOp::from(op)) }
    }

    /// # Safety
    /// The caller is required to ensure the safety of the validation operation
    /// on this memory range.
    unsafe fn validate_virtual_page_range(
        &self,
        region: MemoryRegion<VirtAddr>,
        op: PageValidateOp,
    ) -> Result<(), SvsmError> {
        // SAFETY: The caller is required to ensure the safety of the memory
        // range.
        unsafe { pvalidate_range(region, PvalidateOp::from(op)) }
    }

    fn flush_tlb(&self, flush_scope: &TlbFlushScope) {
        flush_tlb_scope(flush_scope);
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
        start_rip: u64,
        _transition_page_table: &TransitionPageTable,
    ) -> Result<(), SvsmError> {
        let (vmsa_pa, sev_features) = cpu.alloc_svsm_vmsa(*VTOM as u64, start_rip)?;

        current_ghcb().ap_create(vmsa_pa, cpu.get_apic_id().into(), 0, sev_features)
    }

    fn start_svsm_request_loop(&self) -> bool {
        true
    }

    /// Perfrom a write to a memory-mapped IO area
    ///
    /// # Safety
    ///
    /// Caller must ensure that `vaddr` points to a properly aligned memory location and the
    /// memory accessed is part of a valid MMIO range.
    unsafe fn mmio_write(&self, vaddr: VirtAddr, data: &[u8]) -> Result<(), SvsmError> {
        let paddr = this_cpu().get_pgtable().phys_addr(vaddr)?;

        // SAFETY: We are trusting the caller to ensure validity of `paddr` and alignment of data.
        unsafe { crate::cpu::percpu::current_ghcb().mmio_write(paddr, data) }
    }

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
    ) -> Result<(), SvsmError> {
        let paddr = this_cpu().get_pgtable().phys_addr(vaddr)?;
        // SAFETY: We are trusting the caller to ensure validity of `paddr` and alignment of data.
        unsafe { crate::cpu::percpu::current_ghcb().mmio_read(paddr, data) }
    }

    fn terminate() -> !
    where
        Self: Sized,
    {
        // Since this processor is destined for a fatal termination, there is
        // no reason to preserve interrupt state.  Interrupts can be disabled
        // outright prior to shutdown.
        raw_irqs_disable();
        request_termination_msr();
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

#[derive(Default, Debug)]
pub struct SnpStage2Platform {}

impl SnpStage2Platform {
    pub fn new() -> Self {
        Self {}
    }
}

impl Stage2Platform for SnpStage2Platform {
    fn get_cpuid_page(&self, launch_info: &Stage2LaunchInfo) -> Option<VirtAddr> {
        Some(VirtAddr::from(launch_info.cpuid_page as usize))
    }
}
