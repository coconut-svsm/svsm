// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use super::cpuset::AtomicCpuSet;
use super::gdt::GDT;
use super::ipi::{
    handle_ipi_interrupt, send_ipi, IpiBoard, IpiHelperMut, IpiHelperShared, IpiMessage,
    IpiMessageMut, IpiTarget,
};
use super::isst::Isst;
use super::msr::write_msr;
use super::shadow_stack::{is_cet_ss_supported, ISST_ADDR};
use super::tss::{X86Tss, IST_DF};
use crate::address::{Address, PhysAddr, VirtAddr, VirtPhysPair};
use crate::cpu::control_regs::{read_cr0, read_cr4};
use crate::cpu::efer::read_efer;
use crate::cpu::idt::common::INT_INJ_VECTOR;
use crate::cpu::tss::TSS_LIMIT;
use crate::cpu::vmsa::{init_guest_vmsa, init_svsm_vmsa};
use crate::cpu::vmsa::{svsm_code_segment, svsm_data_segment, svsm_gdt_segment, svsm_idt_segment};
use crate::cpu::x86::{ApicAccess, X86Apic};
use crate::cpu::{IrqGuard, IrqState, LocalApic};
use crate::error::{ApicError, SvsmError};
use crate::hyperv;
use crate::hyperv::{HypercallPagesGuard, IS_HYPERV};
use crate::locking::{LockGuard, RWLock, RWLockIrqSafe, SpinLock};
use crate::mm::page_visibility::SharedBox;
use crate::mm::pagetable::{PTEntryFlags, PageTable};
use crate::mm::virtualrange::VirtualRange;
use crate::mm::vm::{
    Mapping, ShadowStackInit, VMKernelShadowStack, VMKernelStack, VMPhysMem, VMRMapping,
    VMReserved, VMR,
};
use crate::mm::{
    virt_to_phys, PageBox, SVSM_CONTEXT_SWITCH_SHADOW_STACK, SVSM_CONTEXT_SWITCH_STACK,
    SVSM_PERCPU_BASE, SVSM_PERCPU_CAA_BASE, SVSM_PERCPU_END, SVSM_PERCPU_TEMP_BASE_2M,
    SVSM_PERCPU_TEMP_BASE_4K, SVSM_PERCPU_TEMP_END_2M, SVSM_PERCPU_TEMP_END_4K,
    SVSM_PERCPU_VMSA_BASE, SVSM_SHADOW_STACKS_INIT_TASK, SVSM_SHADOW_STACK_ISST_DF_BASE,
    SVSM_STACK_IST_DF_BASE,
};
use crate::platform::{halt, SvsmPlatform, SVSM_PLATFORM};
use crate::sev::ghcb::{GhcbPage, GHCB};
use crate::sev::hv_doorbell::{allocate_hv_doorbell_page, HVDoorbell};
use crate::sev::utils::RMPFlags;
use crate::sev::vmsa::{VMSAControl, VmsaPage};
use crate::task::{schedule, schedule_task, RunQueue, Task, TaskPointer};
use crate::types::{
    PAGE_SHIFT, PAGE_SHIFT_2M, PAGE_SIZE, PAGE_SIZE_2M, SVSM_TR_ATTRIBUTES, SVSM_TSS,
};
use crate::utils::MemoryRegion;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::asm;
use core::cell::{Cell, OnceCell, Ref, RefCell, RefMut, UnsafeCell};
use core::mem::size_of;
use core::ptr;
use core::slice::Iter;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use cpuarch::vmsa::VMSA;

// PERCPU areas virtual addresses into shared memory
pub static PERCPU_AREAS: PerCpuAreas = PerCpuAreas::new();

// We use an UnsafeCell to allow for a static with interior
// mutability. Normally, we would need to guarantee synchronization
// on the backing datatype, but this is not needed because writes to
// the structure only occur at initialization, from CPU 0, and reads
// should only occur after all writes are done.
#[derive(Debug)]
pub struct PerCpuAreas {
    areas: UnsafeCell<Vec<&'static PerCpuShared>>,
}

unsafe impl Sync for PerCpuAreas {}

impl PerCpuAreas {
    const fn new() -> Self {
        Self {
            areas: UnsafeCell::new(Vec::new()),
        }
    }

    /// # Safety
    /// The areas vector obtained here is not multi-thread safe, so the caller
    /// must guarantee that is not used in a context that expects multiwthread
    /// safety.
    unsafe fn get_areas(&self) -> &Vec<&'static PerCpuShared> {
        // SAFETY: the caller guarantees that accessing the unsafe cell is
        // appropriate.
        unsafe { &*self.areas.get() }
    }

    /// # Safety
    /// This function can only be invoked before any other processors have
    /// started.  Otherwise, accesses to the areas vector will not be safe.
    pub unsafe fn create_new(&self, apic_id: u32) -> &'static PerCpuShared {
        // SAFETY: the caller guarantees that it is safe to obtain a mutable
        // reference to the areas vector.
        let areas = unsafe { &mut *self.areas.get() };

        // Allocate a new shared per-CPU area to describe the APIC ID being
        // created.  The CPU index will be the next in sequence ased on the
        // size of the vector.  The new shared per-CPU area is allocated on
        // the heap so it is globally visible.
        let cpu_index = areas.len();
        let percpu_shared = Box::leak(Box::new(PerCpuShared::new(apic_id, cpu_index)));

        // Leak the box so the allocation persists with a static lifetime,
        // and install the allocated per-CPU area into the areas vector.
        areas.push(percpu_shared);

        percpu_shared
    }

    pub fn len(&self) -> usize {
        // SAFETY: it is safe to obtain a shared reference to the areas
        // vector because callers attempting to mutate the vector guarantee
        // that they cannot race with iteration.
        let areas = unsafe { self.get_areas() };
        areas.len()
    }

    pub fn is_empty(&self) -> bool {
        // SAFETY: it is safe to obtain a shared reference to the areas
        // vector because callers attempting to mutate the vector guarantee
        // that they cannot race with iteration.
        let areas = unsafe { self.get_areas() };
        areas.is_empty()
    }

    pub fn iter(&self) -> Iter<'_, &'static PerCpuShared> {
        // SAFETY: it is safe to obtain a shared reference to the areas
        // vector because callers attempting to mutate the vector guarantee
        // that they cannot race with iteration.
        let areas = unsafe { self.get_areas() };
        areas.iter()
    }

    // Fails if no such area exists or its address is NULL
    pub fn get_by_apic_id(&self, apic_id: u32) -> Option<&'static PerCpuShared> {
        // For this to not produce UB the only invariant we must
        // uphold is that there are no mutations or mutable aliases
        // going on when casting via as_ref(). This only happens via
        // Self::push(), which is intentionally unsafe and private.
        self.iter()
            .find(|shared| shared.apic_id() == apic_id)
            .copied()
    }

    /// Callers are expected to specify a valid CPU index.
    pub fn get_by_cpu_index(&self, index: usize) -> &'static PerCpuShared {
        // SAFETY: it is safe to obtain a shared reference to the areas
        // vector because callers attempting to mutate the vector guarantee
        // that they cannot race with iteration.
        let areas = unsafe { self.get_areas() };
        areas[index]
    }
}

#[derive(Debug)]
struct IstStacks {
    double_fault_stack: Cell<Option<VirtAddr>>,
    double_fault_shadow_stack: Cell<Option<VirtAddr>>,
}

impl IstStacks {
    const fn new() -> Self {
        IstStacks {
            double_fault_stack: Cell::new(None),
            double_fault_shadow_stack: Cell::new(None),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GuestVmsaRef {
    vmsa: Option<PhysAddr>,
    caa: Option<PhysAddr>,
    generation: u64,
    gen_in_use: u64,
}

impl GuestVmsaRef {
    pub const fn new() -> Self {
        GuestVmsaRef {
            vmsa: None,
            caa: None,
            generation: 1,
            gen_in_use: 0,
        }
    }

    pub fn needs_update(&self) -> bool {
        self.generation != self.gen_in_use
    }

    pub fn update_vmsa(&mut self, paddr: Option<PhysAddr>) {
        self.vmsa = paddr;
        self.generation += 1;
    }

    pub fn update_caa(&mut self, paddr: Option<PhysAddr>) {
        self.caa = paddr;
        self.generation += 1;
    }

    pub fn update_vmsa_caa(&mut self, vmsa: Option<PhysAddr>, caa: Option<PhysAddr>) {
        self.vmsa = vmsa;
        self.caa = caa;
        self.generation += 1;
    }

    pub fn set_updated(&mut self) {
        self.gen_in_use = self.generation;
    }

    pub fn vmsa_phys(&self) -> Option<PhysAddr> {
        self.vmsa
    }

    pub fn caa_phys(&self) -> Option<PhysAddr> {
        self.caa
    }

    pub fn vmsa(&mut self) -> &mut VMSA {
        assert!(self.vmsa.is_some());
        // SAFETY: this function takes &mut self, so only one mutable
        // reference to the underlying VMSA can exist.
        unsafe { SVSM_PERCPU_VMSA_BASE.as_mut_ptr::<VMSA>().as_mut().unwrap() }
    }

    pub fn caa_addr(&self) -> Option<VirtAddr> {
        let caa_phys = self.caa_phys()?;
        let offset = caa_phys.page_offset();

        Some(SVSM_PERCPU_CAA_BASE + offset)
    }
}

#[derive(Debug)]
pub struct PerCpuShared {
    apic_id: u32,
    cpu_index: usize,
    guest_vmsa: SpinLock<GuestVmsaRef>,
    online: AtomicBool,
    ipi_irr: [AtomicU32; 8],
    ipi_pending: AtomicBool,
    nmi_pending: AtomicBool,

    // A set of CPUs that have requested IPI handling by this CPU.
    ipi_requests: AtomicCpuSet,

    // A bulletin board holding the state of an IPI message to send to other
    // CPUs.
    ipi_board: IpiBoard,
}

impl PerCpuShared {
    fn new(apic_id: u32, cpu_index: usize) -> Self {
        PerCpuShared {
            apic_id,
            cpu_index,
            guest_vmsa: SpinLock::new(GuestVmsaRef::new()),
            online: AtomicBool::new(false),
            ipi_irr: core::array::from_fn(|_| AtomicU32::new(0)),
            ipi_pending: AtomicBool::new(false),
            nmi_pending: AtomicBool::new(false),
            ipi_requests: Default::default(),
            ipi_board: IpiBoard::default(),
        }
    }

    pub const fn apic_id(&self) -> u32 {
        self.apic_id
    }

    pub const fn cpu_index(&self) -> usize {
        self.cpu_index
    }

    pub fn update_guest_vmsa_caa(&self, vmsa: PhysAddr, caa: PhysAddr) {
        let mut locked = self.guest_vmsa.lock();
        locked.update_vmsa_caa(Some(vmsa), Some(caa));
    }

    pub fn update_guest_vmsa(&self, vmsa: PhysAddr) {
        let mut locked = self.guest_vmsa.lock();
        locked.update_vmsa(Some(vmsa));
    }

    pub fn update_guest_caa(&self, caa: PhysAddr) {
        let mut locked = self.guest_vmsa.lock();
        locked.update_caa(Some(caa));
    }

    pub fn clear_guest_vmsa_if_match(&self, paddr: PhysAddr) {
        let mut locked = self.guest_vmsa.lock();
        if locked.vmsa.is_none() {
            return;
        }

        let vmsa_phys = locked.vmsa_phys();
        if vmsa_phys.unwrap() == paddr {
            locked.update_vmsa(None);
        }
    }

    pub fn set_online(&self) {
        self.online.store(true, Ordering::Release);
    }

    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    pub fn request_ipi(&self, vector: u8) {
        let index = vector >> 5;
        let bit = 1u32 << (vector & 31);
        // Request the IPI via the IRR vector before signaling that an IPI has
        // been requested.
        self.ipi_irr[index as usize].fetch_or(bit, Ordering::Relaxed);
        self.ipi_pending.store(true, Ordering::Release);
    }

    pub fn request_nmi(&self) {
        self.nmi_pending.store(true, Ordering::Relaxed);
        self.ipi_pending.store(true, Ordering::Release);
    }

    pub fn ipi_pending(&self) -> bool {
        self.ipi_pending.swap(false, Ordering::Acquire)
    }

    pub fn ipi_irr_vector(&self, index: usize) -> u32 {
        self.ipi_irr[index].swap(0, Ordering::Relaxed)
    }

    pub fn nmi_pending(&self) -> bool {
        self.nmi_pending.swap(false, Ordering::Relaxed)
    }

    pub fn ipi_from(&self, cpu_index: usize) {
        self.ipi_requests.add(cpu_index, Ordering::Release);
    }

    /// # Safety
    /// The IPI board is not `Sync`, so the caller is responsible for ensuring
    /// that a reference to the IPI board is only obtained when it is safe to
    /// do so.
    pub unsafe fn ipi_board(&self) -> &IpiBoard {
        &self.ipi_board
    }
}

const _: () = assert!(size_of::<PerCpu>() <= PAGE_SIZE);

/// CPU-local data.
///
/// This type is not [`Sync`], as its contents will only be accessed from the
/// local CPU, much like thread-local data in an std environment. The only
/// part of the struct that may be accessed from a different CPU is the
/// `shared` field, a reference to which will be stored in [`PERCPU_AREAS`].
#[derive(Debug)]
pub struct PerCpu {
    /// Reference to the `PerCpuShared` that is valid in the global, shared
    /// address space.
    shared: &'static PerCpuShared,

    /// APIC access object
    apic: X86Apic,

    /// PerCpu IRQ state tracking
    irq_state: IrqState,

    pgtbl: RefCell<Option<&'static mut PageTable>>,
    tss: X86Tss,
    isst: Cell<Isst>,
    svsm_vmsa: OnceCell<VmsaPage>,
    reset_ip: Cell<u64>,
    /// PerCpu Virtual Memory Range
    vm_range: VMR,
    /// Address allocator for per-cpu 4k temporary mappings
    pub vrange_4k: RefCell<VirtualRange>,
    /// Address allocator for per-cpu 2m temporary mappings
    pub vrange_2m: RefCell<VirtualRange>,
    /// Task list that has been assigned for scheduling on this CPU
    runqueue: RWLockIrqSafe<RunQueue>,
    /// Local APIC state for APIC emulation if enabled
    guest_apic: RefCell<Option<LocalApic>>,

    /// GHCB page for this CPU.
    ghcb: OnceCell<GhcbPage>,

    /// Hypercall input/output pages for this CPU if running under Hyper-V.
    hypercall_pages: RefCell<Option<(VirtPhysPair, VirtPhysPair)>>,

    /// `#HV` doorbell page for this CPU.
    hv_doorbell: Cell<Option<&'static HVDoorbell>>,

    init_shadow_stack: Cell<Option<VirtAddr>>,
    context_switch_stack: Cell<Option<VirtAddr>>,
    ist: IstStacks,

    /// Stack boundaries of the currently running task.
    current_stack: Cell<MemoryRegion<VirtAddr>>,
}

impl PerCpu {
    /// Creates a new default [`PerCpu`] struct.
    fn new(shared: &'static PerCpuShared) -> Self {
        Self {
            pgtbl: RefCell::new(None),
            apic: X86Apic::default(),
            irq_state: IrqState::new(),
            tss: X86Tss::new(),
            isst: Cell::new(Isst::default()),
            svsm_vmsa: OnceCell::new(),
            reset_ip: Cell::new(0xffff_fff0),
            vm_range: {
                let mut vmr = VMR::new(SVSM_PERCPU_BASE, SVSM_PERCPU_END, PTEntryFlags::GLOBAL);
                vmr.set_per_cpu(true);
                vmr
            },

            vrange_4k: RefCell::new(VirtualRange::new()),
            vrange_2m: RefCell::new(VirtualRange::new()),
            runqueue: RWLockIrqSafe::new(RunQueue::new()),
            guest_apic: RefCell::new(None),

            shared,
            ghcb: OnceCell::new(),
            hypercall_pages: RefCell::new(None),
            hv_doorbell: Cell::new(None),
            init_shadow_stack: Cell::new(None),
            context_switch_stack: Cell::new(None),
            ist: IstStacks::new(),
            current_stack: Cell::new(MemoryRegion::new(VirtAddr::null(), 0)),
        }
    }

    /// Creates a new default [`PerCpu`] struct, allocates it via the page
    /// allocator and adds it to the global per-cpu area list.
    pub fn alloc(shared: &'static PerCpuShared) -> Result<&'static Self, SvsmError> {
        let page = PageBox::try_new(Self::new(shared))?;
        let percpu = PageBox::leak(page);
        Ok(percpu)
    }

    pub fn shared(&self) -> &PerCpuShared {
        self.shared
    }

    pub fn initialize_apic(&self, accessor: &'static dyn ApicAccess) {
        self.apic.set_accessor(accessor);
    }

    /// Get a reference to the [`X86Apic`] object for this cpu.
    ///
    /// # Returns
    ///
    /// Reference to the [`X86Apic`] object of the local CPU.
    pub fn get_apic(&self) -> &X86Apic {
        &self.apic
    }

    /// Disables IRQs on the current CPU. Keeps track of the nesting level and
    /// the original IRQ state.
    ///
    /// Caller needs to make sure to match every `disable()` call with an
    /// `enable()` call.
    #[inline(always)]
    pub fn irqs_disable(&self) {
        self.irq_state.disable();
    }

    /// Reduces IRQ-disable nesting level on the current CPU and restores the
    /// original IRQ state when the level reaches 0.
    ///
    /// Caller needs to make sure to match every `disable()` call with an
    /// `enable()` call.
    #[inline(always)]
    pub fn irqs_enable(&self) {
        self.irq_state.enable();
    }

    /// Increments IRQ-disable nesting level on the current CPU without
    /// disabling interrupts.  This is used by exception and interrupt dispatch
    /// routines that have already disabled interrupts.
    ///
    /// Caller needs to make sure to match every `push_nesting()` call with a
    /// `pop_nesting()` call.
    #[inline(always)]
    pub fn irqs_push_nesting(&self, was_enabled: bool) {
        self.irq_state.push_nesting(was_enabled);
    }

    /// Reduces IRQ-disable nesting level on the current CPU without restoring
    /// the original IRQ state original IRQ state.  This is used by exception
    /// and interrupt dispatch routines that will restore interrupt state
    /// naturally.
    ///
    /// Caller needs to make sure to match every `disable()` call with a
    /// `pop_state()` call.
    #[inline(always)]
    pub fn irqs_pop_nesting(&self) {
        let _ = self.irq_state.pop_nesting();
    }

    /// Get IRQ-disable nesting count on the current CPU
    ///
    /// # Returns
    ///
    /// Current nesting depth of irq_disable() calls.
    pub fn irq_nesting_count(&self) -> i32 {
        self.irq_state.count()
    }

    /// Raises TPR on the current CPU.  Keeps track of the nesting level.
    ///
    /// The caller must ensure that every `raise_tpr()` call is followed by a
    /// matching call to `lower_tpr()`.
    #[inline(always)]
    pub fn raise_tpr(&self, tpr_value: usize) {
        self.irq_state.raise_tpr(tpr_value);
    }

    /// Lowers TPR from the current level to the new level required by the
    /// current nesting state.
    ///
    /// The caller must ensure that a `lower_tpr()` call balances a preceding
    /// `raise_tpr()` call to the indicated level.
    ///
    /// * `tpr_value` - The TPR from which the caller would like to lower.
    ///   Must be less than or equal to the current TPR.
    #[inline(always)]
    pub fn lower_tpr(&self, tpr_value: usize) {
        self.irq_state.lower_tpr(tpr_value);
    }

    /// Sends an IPI message to multiple CPUs.
    ///
    /// * `target_set` - The set of CPUs to which to send the IPI.
    /// * `ipi_message` - The message to send.
    pub fn send_multicast_ipi<M: IpiMessage + Sync>(
        &self,
        target_set: IpiTarget<'_>,
        ipi_message: &M,
    ) {
        let mut ipi_helper = IpiHelperShared::new(ipi_message);
        send_ipi(
            target_set,
            self.shared.cpu_index,
            &mut ipi_helper,
            &self.shared.ipi_board,
        );
    }

    /// Sends an IPI message to a single CPU.  Because only a single CPU can
    /// receive the message, the message object can be mutable.
    ///
    /// # Arguments
    /// * `cpu_index` - The index of the CPU to receive the message.
    /// * `ipi_message` - The message to send.
    pub fn send_unicast_ipi<M: IpiMessageMut>(&self, cpu_index: usize, ipi_message: &mut M) {
        let mut ipi_helper = IpiHelperMut::new(ipi_message);
        send_ipi(
            IpiTarget::Single(cpu_index),
            self.shared.cpu_index,
            &mut ipi_helper,
            &self.shared.ipi_board,
        );
    }

    /// Handles an IPI interrupt.
    pub fn handle_ipi_interrupt(&self) {
        handle_ipi_interrupt(&self.shared.ipi_requests);
    }

    /// Sets up the CPU-local GHCB page.
    pub fn setup_ghcb(&self) -> Result<(), SvsmError> {
        let page = GhcbPage::new()?;
        self.ghcb
            .set(page)
            .expect("Attempted to reinitialize the GHCB");
        Ok(())
    }

    fn ghcb(&self) -> Option<&GhcbPage> {
        self.ghcb.get()
    }

    /// Allocates hypercall input/output pages for this CPU.
    pub fn allocate_hypercall_pages(&self) -> Result<(), SvsmError> {
        let pages = SharedBox::<[u8; PAGE_SIZE * 2]>::try_new_zeroed()?.leak();
        let p1 = VirtPhysPair::new(pages.as_ptr().into());
        let p2 = VirtPhysPair::new(p1.vaddr + PAGE_SIZE);
        *self.hypercall_pages.borrow_mut() = Some((p1, p2));
        Ok(())
    }

    pub fn get_hypercall_pages(&self) -> HypercallPagesGuard<'_> {
        // The hypercall page cell is never mutated, but is borrowed mutably
        // to ensure that only a single reference can ever be taken at a time.
        let page_ref: RefMut<'_, Option<(VirtPhysPair, VirtPhysPair)>> =
            self.hypercall_pages.borrow_mut();
        // SAFETY: the virtual addresses were allocated when the hypercall
        // pages were configured, and the physical addresses were captured at
        // that time.
        unsafe { HypercallPagesGuard::new(RefMut::map(page_ref, |o| o.as_mut().unwrap())) }
    }

    pub fn hv_doorbell(&self) -> Option<&'static HVDoorbell> {
        self.hv_doorbell.get()
    }

    pub fn process_hv_events_if_required(&self) {
        if let Some(doorbell) = self.hv_doorbell.get() {
            doorbell.process_if_required(&self.irq_state);
        }
    }

    /// Gets a pointer to the location of the HV doorbell pointer in the
    /// PerCpu structure. Pointers and references have the same layout, so
    /// the return type is equivalent to `*const *const HVDoorbell`.
    pub fn hv_doorbell_addr(&self) -> *const &'static HVDoorbell {
        self.hv_doorbell.as_ptr().cast()
    }

    pub fn get_top_of_shadow_stack(&self) -> VirtAddr {
        self.init_shadow_stack.get().unwrap()
    }

    pub fn get_top_of_context_switch_stack(&self) -> VirtAddr {
        self.context_switch_stack.get().unwrap()
    }

    pub fn get_top_of_df_stack(&self) -> VirtAddr {
        self.ist.double_fault_stack.get().unwrap()
    }

    pub fn get_top_of_df_shadow_stack(&self) -> VirtAddr {
        self.ist.double_fault_shadow_stack.get().unwrap()
    }

    pub fn get_current_stack(&self) -> MemoryRegion<VirtAddr> {
        self.current_stack.get()
    }

    pub fn set_current_stack(&self, stack: MemoryRegion<VirtAddr>) {
        self.current_stack.set(stack);
    }

    pub fn get_cpu_index(&self) -> usize {
        self.shared.cpu_index()
    }

    pub fn get_apic_id(&self) -> u32 {
        self.shared().apic_id()
    }

    pub fn init_page_table(&self, pgtable: PageBox<PageTable>) -> Result<(), SvsmError> {
        // SAFETY: The per-CPU address range is fully aligned to top-level
        // paging boundaries.
        unsafe {
            self.vm_range.initialize()?;
        }
        self.set_pgtable(PageBox::leak(pgtable));

        Ok(())
    }

    pub fn set_pgtable(&self, pgtable: &'static mut PageTable) {
        *self.pgtbl.borrow_mut() = Some(pgtable);
    }

    fn allocate_stack(&self, base: VirtAddr) -> Result<VirtAddr, SvsmError> {
        let stack = VMKernelStack::new()?;
        let top_of_stack = stack.top_of_stack(base);
        let mapping = Arc::new(Mapping::new(stack));

        self.vm_range.insert_at(base, mapping)?;

        Ok(top_of_stack)
    }

    fn allocate_shadow_stack(
        &self,
        base: VirtAddr,
        init: ShadowStackInit,
    ) -> Result<VirtAddr, SvsmError> {
        let (shadow_stack, _, ssp) = VMKernelShadowStack::new(base, init)?;
        self.vm_range
            .insert_at(base, Arc::new(Mapping::new(shadow_stack)))?;
        Ok(ssp)
    }

    fn allocate_init_shadow_stack(&self) -> Result<(), SvsmError> {
        let init_stack =
            Some(self.allocate_shadow_stack(SVSM_SHADOW_STACKS_INIT_TASK, ShadowStackInit::Init)?);
        self.init_shadow_stack.set(init_stack);
        Ok(())
    }

    fn allocate_context_switch_stack(&self) -> Result<(), SvsmError> {
        let cs_stack = Some(self.allocate_stack(SVSM_CONTEXT_SWITCH_STACK)?);
        self.context_switch_stack.set(cs_stack);
        Ok(())
    }

    fn allocate_context_switch_shadow_stack(&self) -> Result<(), SvsmError> {
        self.allocate_shadow_stack(
            SVSM_CONTEXT_SWITCH_SHADOW_STACK,
            ShadowStackInit::ContextSwitch,
        )?;
        Ok(())
    }

    fn allocate_ist_stacks(&self) -> Result<(), SvsmError> {
        let double_fault_stack = self.allocate_stack(SVSM_STACK_IST_DF_BASE)?;
        self.ist.double_fault_stack.set(Some(double_fault_stack));

        Ok(())
    }

    fn allocate_isst_shadow_stacks(&self) -> Result<(), SvsmError> {
        let double_fault_shadow_stack =
            self.allocate_shadow_stack(SVSM_SHADOW_STACK_ISST_DF_BASE, ShadowStackInit::Exception)?;
        self.ist
            .double_fault_shadow_stack
            .set(Some(double_fault_shadow_stack));

        Ok(())
    }

    pub fn get_pgtable(&self) -> RefMut<'_, PageTable> {
        RefMut::map(self.pgtbl.borrow_mut(), |pgtbl| {
            &mut **pgtbl.as_mut().unwrap()
        })
    }

    /// Registers an already set up GHCB page for this CPU.
    ///
    /// # Panics
    ///
    /// Panics if the GHCB for this CPU has not been set up via
    /// [`PerCpu::setup_ghcb()`].
    pub fn register_ghcb(&self) -> Result<(), SvsmError> {
        self.ghcb().unwrap().register()
    }

    pub fn setup_hv_doorbell(&self) -> Result<(), SvsmError> {
        let doorbell = allocate_hv_doorbell_page(current_ghcb())?;
        assert!(
            self.hv_doorbell.get().is_none(),
            "Attempted to reinitialize the HV doorbell page"
        );
        self.hv_doorbell.set(Some(doorbell));
        Ok(())
    }

    fn setup_tss(&self) {
        let double_fault_stack = self.get_top_of_df_stack();
        // SAFETY: the stck pointer is known to be correct.
        unsafe {
            self.tss.set_ist_stack(IST_DF, double_fault_stack);
        }
    }

    fn setup_isst(&self) {
        let double_fault_shadow_stack = self.get_top_of_df_shadow_stack();
        let mut isst = self.isst.get();
        isst.set(IST_DF, double_fault_shadow_stack);
        self.isst.set(isst);
    }

    pub fn map_self_stage2(&self) -> Result<(), SvsmError> {
        let vaddr = VirtAddr::from(ptr::from_ref(self));
        let paddr = virt_to_phys(vaddr);
        let flags = PTEntryFlags::data();
        self.get_pgtable().map_4k(SVSM_PERCPU_BASE, paddr, flags)
    }

    pub fn map_self(&self) -> Result<(), SvsmError> {
        let vaddr = VirtAddr::from(ptr::from_ref(self));
        let paddr = virt_to_phys(vaddr);
        let self_mapping = Arc::new(VMPhysMem::new_mapping(paddr, PAGE_SIZE, true));
        self.vm_range.insert_at(SVSM_PERCPU_BASE, self_mapping)?;
        Ok(())
    }

    fn initialize_vm_ranges(&self) -> Result<(), SvsmError> {
        let size_4k = SVSM_PERCPU_TEMP_END_4K - SVSM_PERCPU_TEMP_BASE_4K;
        let temp_mapping_4k = Arc::new(VMReserved::new_mapping(size_4k));
        self.vm_range
            .insert_at(SVSM_PERCPU_TEMP_BASE_4K, temp_mapping_4k)?;

        let size_2m = SVSM_PERCPU_TEMP_END_2M - SVSM_PERCPU_TEMP_BASE_2M;
        let temp_mapping_2m = Arc::new(VMReserved::new_mapping(size_2m));
        self.vm_range
            .insert_at(SVSM_PERCPU_TEMP_BASE_2M, temp_mapping_2m)?;

        Ok(())
    }

    fn finish_page_table(&self) {
        let mut pgtable = self.get_pgtable();
        self.vm_range.populate(&mut pgtable);
    }

    pub fn dump_vm_ranges(&self) {
        self.vm_range.dump_ranges();
    }

    pub fn setup(
        &self,
        platform: &dyn SvsmPlatform,
        pgtable: PageBox<PageTable>,
    ) -> Result<(), SvsmError> {
        self.init_page_table(pgtable)?;

        // Map PerCpu data in own page-table
        self.map_self()?;

        // Reserve ranges for temporary mappings
        self.initialize_vm_ranges()?;

        if is_cet_ss_supported() {
            self.allocate_init_shadow_stack()?;
        }

        // Allocate per-cpu context switch stack
        self.allocate_context_switch_stack()?;

        if is_cet_ss_supported() {
            self.allocate_context_switch_shadow_stack()?;
        }

        // Allocate IST stacks
        self.allocate_ist_stacks()?;

        // Setup TSS
        self.setup_tss();

        if is_cet_ss_supported() {
            // Allocate ISST shadow stacks
            self.allocate_isst_shadow_stacks()?;

            // Setup ISST
            self.setup_isst();
        }

        // Initialize allocator for temporary mappings
        self.virt_range_init();

        self.finish_page_table();

        // Complete platform-specific initialization.
        platform.setup_percpu(self)?;

        // Allocate hypercall pages if running on Hyper-V, unless this is the
        // BSP (where they will be allocated later).
        if self.shared.cpu_index() != 0 && *IS_HYPERV {
            self.allocate_hypercall_pages()?;
        }

        Ok(())
    }

    // Setup code which needs to run on the target CPU
    pub fn setup_on_cpu(&self, platform: &dyn SvsmPlatform) -> Result<(), SvsmError> {
        platform.setup_percpu_current(self)?;
        assert!(self.get_apic().id() == self.get_apic_id());
        Ok(())
    }

    pub fn setup_idle_task(&self, entry: extern "C" fn(usize)) -> Result<(), SvsmError> {
        let idle_task = Task::create(self, entry, self.shared.cpu_index, String::from("idle"))?;
        self.runqueue.lock_read().set_idle_task(idle_task);
        Ok(())
    }

    pub fn load_gdt_tss(&'static self, init_gdt: bool) {
        // Create a temporary GDT to use to configure the TSS.
        let mut gdt = GDT::new();
        gdt.load();
        // Load the GDT selectors if requested.
        if init_gdt {
            gdt.load_selectors();
        }
        gdt.load_tss(&self.tss);
    }

    pub fn load_isst(&self) {
        let isst = self.isst.as_ptr();
        // SAFETY: ISST is already setup when this is called.
        unsafe { write_msr(ISST_ADDR, isst as u64) };
    }

    pub fn load(&'static self) {
        // SAFETY: along with the page table we are also uploading the right
        // TSS and ISST to ensure a memory safe execution state
        unsafe { self.get_pgtable().load() };
        self.load_gdt_tss(false);
        if is_cet_ss_supported() {
            self.load_isst();
        }
    }

    pub fn set_reset_ip(&self, reset_ip: u64) {
        self.reset_ip.set(reset_ip);
    }

    /// Fill in the initial context structure for the SVSM.
    pub fn get_initial_context(&self, start_rip: u64) -> hyperv::HvInitialVpContext {
        let data_segment = svsm_data_segment();

        hyperv::HvInitialVpContext {
            rip: start_rip,
            // Use the context switch stack as its initial stack. This stack
            // will later serve as the transitory stack during context
            // switching. It is accessible after switching to the first task's
            // page table because it resides in the PerCpu virtual range.
            //
            // See switch_to() for details.
            rsp: self.get_top_of_context_switch_stack().into(),
            rflags: 2,

            cs: svsm_code_segment(),
            ss: data_segment,
            ds: data_segment,
            es: data_segment,
            fs: data_segment,
            gs: data_segment,
            tr: self.svsm_tr_segment(),

            gdtr: svsm_gdt_segment(),
            idtr: svsm_idt_segment(),

            cr0: read_cr0().bits(),
            cr3: self.get_pgtable().cr3_value().into(),
            cr4: read_cr4().bits(),
            efer: read_efer().bits(),
            pat: 0x0007040600070406u64,

            ..Default::default()
        }
    }

    /// Allocates and initializes a new VMSA for this CPU. Returns its
    /// physical address and SEV features. Returns an error if allocation
    /// fails of this CPU's VMSA was already initialized.
    pub fn alloc_svsm_vmsa(&self, vtom: u64, start_rip: u64) -> Result<(PhysAddr, u64), SvsmError> {
        if self.svsm_vmsa.get().is_some() {
            // FIXME: add a more explicit error variant for this condition
            return Err(SvsmError::Mem);
        }

        let mut vmsa = VmsaPage::new(RMPFlags::VMPL1)?;
        let paddr = vmsa.paddr();

        // Initialize VMSA
        let context = self.get_initial_context(start_rip);
        init_svsm_vmsa(&mut vmsa, vtom, &context);
        vmsa.enable();

        let sev_features = vmsa.sev_features;

        // We already checked that the VMSA is unset
        self.svsm_vmsa.set(vmsa).unwrap();

        Ok((paddr, sev_features))
    }

    fn unmap_guest_vmsa(&self) {
        assert!(self.shared().cpu_index == this_cpu().get_cpu_index());
        // Ignore errors - the mapping might or might not be there
        let _ = self.vm_range.remove(SVSM_PERCPU_VMSA_BASE);
    }

    fn map_guest_vmsa(&self, paddr: PhysAddr) -> Result<(), SvsmError> {
        assert!(self.shared().cpu_index == this_cpu().get_cpu_index());
        let vmsa_mapping = Arc::new(VMPhysMem::new_mapping(paddr, PAGE_SIZE, true));
        self.vm_range
            .insert_at(SVSM_PERCPU_VMSA_BASE, vmsa_mapping)?;

        Ok(())
    }

    pub fn guest_vmsa_ref(&self) -> LockGuard<'_, GuestVmsaRef> {
        self.shared().guest_vmsa.lock()
    }

    pub fn alloc_guest_vmsa(&self) -> Result<(), SvsmError> {
        // Enable alternate injection if the hypervisor supports it.
        let use_alternate_injection = SVSM_PLATFORM.query_apic_registration_state();
        if use_alternate_injection {
            self.guest_apic.replace(Some(LocalApic::new()));

            // Configure the interrupt injection vector.
            let ghcb = self.ghcb().unwrap();
            ghcb.configure_interrupt_injection(INT_INJ_VECTOR)?;
        }

        let mut vmsa = VmsaPage::new(RMPFlags::GUEST_VMPL)?;
        let paddr = vmsa.paddr();

        init_guest_vmsa(&mut vmsa, self.reset_ip.get(), use_alternate_injection);

        self.shared().update_guest_vmsa(paddr);
        let _ = VmsaPage::leak(vmsa);

        Ok(())
    }

    /// Returns a shared reference to the local APIC, or `None` if APIC
    /// emulation is not enabled.
    fn guest_apic(&self) -> Option<Ref<'_, LocalApic>> {
        let apic = self.guest_apic.borrow();
        Ref::filter_map(apic, Option::as_ref).ok()
    }

    /// Returns a mutable reference to the local APIC, or `None` if APIC
    /// emulation is not enabled.
    fn guest_apic_mut(&self) -> Option<RefMut<'_, LocalApic>> {
        let apic = self.guest_apic.borrow_mut();
        RefMut::filter_map(apic, Option::as_mut).ok()
    }

    fn unmap_caa(&self) {
        // Ignore errors - the mapping might or might not be there
        let _ = self.vm_range.remove(SVSM_PERCPU_CAA_BASE);
    }

    fn map_guest_caa(&self, paddr: PhysAddr) -> Result<(), SvsmError> {
        self.unmap_caa();

        let caa_mapping = Arc::new(VMPhysMem::new_mapping(paddr, PAGE_SIZE, true));
        self.vm_range.insert_at(SVSM_PERCPU_CAA_BASE, caa_mapping)?;

        Ok(())
    }

    pub fn update_guest_mappings(&self) -> Result<(), SvsmError> {
        let mut locked = self.guest_vmsa_ref();
        let mut ret = Ok(());

        if !locked.needs_update() {
            // If there is no VMSA, then the update request must be considered a
            // failure even though no work was required.
            return match locked.vmsa_phys() {
                Some(_) => Ok(()),
                None => Err(SvsmError::MissingVMSA),
            };
        }

        self.unmap_guest_vmsa();
        self.unmap_caa();

        match locked.vmsa_phys() {
            Some(paddr) => self.map_guest_vmsa(paddr)?,
            None => ret = Err(SvsmError::MissingVMSA),
        }

        if let Some(paddr) = locked.caa_phys() {
            self.map_guest_caa(paddr)?
        }

        locked.set_updated();

        ret
    }

    pub fn disable_apic_emulation(&self) {
        if let Some(mut apic) = self.guest_apic_mut() {
            let mut vmsa_ref = self.guest_vmsa_ref();
            let caa_addr = vmsa_ref.caa_addr();
            let vmsa = vmsa_ref.vmsa();
            apic.disable_apic_emulation(vmsa, caa_addr);
        }
    }

    pub fn clear_pending_interrupts(&self) {
        if let Some(mut apic) = self.guest_apic_mut() {
            let mut vmsa_ref = self.guest_vmsa_ref();
            let caa_addr = vmsa_ref.caa_addr();
            let vmsa = vmsa_ref.vmsa();
            apic.check_delivered_interrupts(vmsa, caa_addr);
        }
    }

    pub fn update_apic_emulation(&self, vmsa: &mut VMSA, caa_addr: Option<VirtAddr>) {
        if let Some(mut apic) = self.guest_apic_mut() {
            apic.present_interrupts(self.shared(), vmsa, caa_addr);
        }
    }

    pub fn use_apic_emulation(&self) -> bool {
        self.guest_apic().is_some()
    }

    pub fn read_apic_register(&self, register: u64) -> Result<u64, SvsmError> {
        let mut vmsa_ref = self.guest_vmsa_ref();
        let caa_addr = vmsa_ref.caa_addr();
        let vmsa = vmsa_ref.vmsa();
        self.guest_apic_mut()
            .ok_or(SvsmError::Apic(ApicError::Disabled))?
            .read_register(self.shared(), vmsa, caa_addr, register)
    }

    pub fn write_apic_register(&self, register: u64, value: u64) -> Result<(), SvsmError> {
        let mut vmsa_ref = self.guest_vmsa_ref();
        let caa_addr = vmsa_ref.caa_addr();
        let vmsa = vmsa_ref.vmsa();
        self.guest_apic_mut()
            .ok_or(SvsmError::Apic(ApicError::Disabled))?
            .write_register(vmsa, caa_addr, register, value)
    }

    pub fn configure_apic_vector(&self, vector: u8, allowed: bool) -> Result<(), SvsmError> {
        self.guest_apic_mut()
            .ok_or(SvsmError::Apic(ApicError::Disabled))?
            .configure_vector(vector, allowed);
        Ok(())
    }

    fn svsm_tr_segment(&self) -> hyperv::HvSegmentRegister {
        hyperv::HvSegmentRegister {
            selector: SVSM_TSS,
            attributes: SVSM_TR_ATTRIBUTES,
            limit: TSS_LIMIT as u32,
            base: &raw const self.tss as u64,
        }
    }

    fn virt_range_init(&self) {
        // Initialize 4k range
        let page_count = (SVSM_PERCPU_TEMP_END_4K - SVSM_PERCPU_TEMP_BASE_4K) / PAGE_SIZE;
        assert!(page_count <= VirtualRange::CAPACITY);
        self.vrange_4k
            .borrow_mut()
            .init(SVSM_PERCPU_TEMP_BASE_4K, page_count, PAGE_SHIFT);

        // Initialize 2M range
        let page_count = (SVSM_PERCPU_TEMP_END_2M - SVSM_PERCPU_TEMP_BASE_2M) / PAGE_SIZE_2M;
        assert!(page_count <= VirtualRange::CAPACITY);
        self.vrange_2m
            .borrow_mut()
            .init(SVSM_PERCPU_TEMP_BASE_2M, page_count, PAGE_SHIFT_2M);
    }

    /// Create a new virtual memory mapping in the PerCpu VMR
    ///
    /// # Arguments
    ///
    /// * `mapping` - The mapping to insert into the PerCpu VMR
    ///
    /// # Returns
    ///
    /// On success, a new ['VMRMapping'} that provides a virtual memory address for
    /// the mapping which remains valid until the ['VRMapping'] is dropped.
    ///
    /// On error, an ['SvsmError'].
    pub fn new_mapping(&self, mapping: Arc<Mapping>) -> Result<VMRMapping<'_>, SvsmError> {
        VMRMapping::new(&self.vm_range, mapping)
    }

    /// Add the PerCpu virtual range into the provided pagetable
    ///
    /// # Arguments
    ///
    /// * `pt` - The page table to populate the the PerCpu range into
    pub fn populate_page_table(&self, pt: &mut PageTable) {
        self.vm_range.populate(pt);
    }

    pub fn handle_pf(&self, vaddr: VirtAddr, write: bool) -> Result<(), SvsmError> {
        self.vm_range.handle_page_fault(vaddr, write)
    }

    pub fn schedule_init(&self) -> TaskPointer {
        self.irq_state.set_restore_state(true);
        let task = self.runqueue.lock_write().schedule_init();
        self.set_current_stack(task.stack_bounds());
        task
    }

    pub fn disable_interrupt_use(&self) {
        let guard = IrqGuard::new();
        self.irq_state.set_restore_state(false);
        drop(guard);
    }

    pub fn schedule_prepare(&self) -> Option<(TaskPointer, TaskPointer)> {
        let ret = self.runqueue.lock_write().schedule_prepare();
        if let Some((_, ref next)) = ret {
            self.set_current_stack(next.stack_bounds());
        };
        ret
    }

    pub fn runqueue(&self) -> &RWLockIrqSafe<RunQueue> {
        &self.runqueue
    }

    pub fn current_task(&self) -> TaskPointer {
        self.runqueue.lock_read().current_task()
    }

    /// # Safety
    /// No checks are performed on the stack address.  The caller must
    /// ensure that the address is valid for stack usage.
    pub unsafe fn set_tss_rsp0(&self, addr: VirtAddr) {
        // SAFETY: the caller has guaranteed the correctness of the stack
        // pointer.
        unsafe {
            self.tss.set_rsp0(addr);
        }
    }
}

pub fn this_cpu() -> &'static PerCpu {
    unsafe { &*SVSM_PERCPU_BASE.as_ptr::<PerCpu>() }
}

pub fn try_this_cpu() -> Option<&'static PerCpu> {
    let mut rcx: u64;

    // SAFETY: Inline assembly to test the validity of the PerCpu page.
    // Any #PF generated here is handled by the #PF handler and it will
    // either return an error in %rcx or crash the system. This however
    // does not impact any state related to memory safety.
    unsafe {
        asm!("1: movq ({0}), {1}",
             "   xorq %rcx, %rcx",
             "2:",
             ".pushsection \"__early_exception_table\",\"a\"",
             ".balign 16",
             ".quad (1b)",
             ".quad (2b)",
             ".popsection",
                in(reg) SVSM_PERCPU_BASE.bits(),
                out(reg) _,
                out("rcx") rcx,
                options(att_syntax, nostack));
    }
    if rcx == 0 {
        Some(this_cpu())
    } else {
        None
    }
}

pub fn this_cpu_shared() -> &'static PerCpuShared {
    this_cpu().shared()
}

/// Disables IRQs on the current CPU. Keeps track of the nesting level and
/// the original IRQ state.
///
/// Caller needs to make sure to match every `irqs_disable()` call with an
/// `irqs_enable()` call.
#[inline(always)]
pub fn irqs_disable() {
    this_cpu().irqs_disable();
}

/// Reduces IRQ-disable nesting level on the current CPU and restores the
/// original IRQ state when the level reaches 0.
///
/// Caller needs to make sure to match every `irqs_disable()` call with an
/// `irqs_enable()` call.
#[inline(always)]
pub fn irqs_enable() {
    this_cpu().irqs_enable();
}

/// Get IRQ-disable nesting count on the current CPU
///
/// # Returns
///
/// Current nesting depth of irq_disable() calls.
pub fn irq_nesting_count() -> i32 {
    this_cpu().irq_nesting_count()
}

/// Raises TPR on the current CPU.  Keeps track of the nesting level.
///
/// The caller must ensure that every `raise_tpr()` call is followed by a
/// matching call to `lower_tpr()`.
#[inline(always)]
pub fn raise_tpr(tpr_value: usize) {
    this_cpu().raise_tpr(tpr_value);
}

/// Lowers TPR from the current level to the new level required by the
/// current nesting state.
///
/// The caller must ensure that a `lower_tpr()` call balances a preceding
/// `raise_tpr()` call to the indicated level.
///
/// * `tpr_value` - The TPR from which the caller would like to lower.
///   Must be less than or equal to the current TPR.
#[inline(always)]
pub fn lower_tpr(tpr_value: usize) {
    this_cpu().lower_tpr(tpr_value);
}

/// Gets the GHCB for this CPU.
///
/// # Panics
///
/// Panics if the GHCB for this CPU has not been set up via
/// [`PerCpu::setup_ghcb()`].
pub fn current_ghcb() -> &'static GHCB {
    this_cpu().ghcb().unwrap()
}

#[derive(Debug, Clone, Copy)]
pub struct VmsaRegistryEntry {
    pub paddr: PhysAddr,
    pub cpu_index: usize,
    pub guest_owned: bool,
    pub in_use: bool,
}

impl VmsaRegistryEntry {
    pub const fn new(paddr: PhysAddr, cpu_index: usize, guest_owned: bool) -> Self {
        VmsaRegistryEntry {
            paddr,
            cpu_index,
            guest_owned,
            in_use: false,
        }
    }
}

// PERCPU VMSAs to apic_id map
pub static PERCPU_VMSAS: PerCpuVmsas = PerCpuVmsas::new();

#[derive(Debug)]
pub struct PerCpuVmsas {
    vmsas: RWLock<Vec<VmsaRegistryEntry>>,
}

impl PerCpuVmsas {
    const fn new() -> Self {
        Self {
            vmsas: RWLock::new(Vec::new()),
        }
    }

    pub fn exists(&self, paddr: PhysAddr) -> bool {
        self.vmsas
            .lock_read()
            .iter()
            .any(|vmsa| vmsa.paddr == paddr)
    }

    pub fn overlaps(&self, region: &MemoryRegion<PhysAddr>) -> bool {
        self.vmsas
            .lock_read()
            .iter()
            .any(|vmsa| region.overlap(&MemoryRegion::new(vmsa.paddr, PAGE_SIZE)))
    }

    pub fn register(
        &self,
        paddr: PhysAddr,
        cpu_index: usize,
        guest_owned: bool,
    ) -> Result<(), SvsmError> {
        let mut guard = self.vmsas.lock_write();
        if guard.iter().any(|vmsa| vmsa.paddr == paddr) {
            return Err(SvsmError::InvalidAddress);
        }

        guard.push(VmsaRegistryEntry::new(paddr, cpu_index, guest_owned));
        Ok(())
    }

    pub fn set_used(&self, paddr: PhysAddr) -> Option<usize> {
        self.vmsas
            .lock_write()
            .iter_mut()
            .find(|vmsa| vmsa.paddr == paddr && !vmsa.in_use)
            .map(|vmsa| {
                vmsa.in_use = true;
                vmsa.cpu_index
            })
    }

    pub fn unregister(&self, paddr: PhysAddr, in_use: bool) -> Result<VmsaRegistryEntry, u64> {
        let mut guard = self.vmsas.lock_write();
        let index = guard
            .iter()
            .position(|vmsa| vmsa.paddr == paddr && vmsa.in_use == in_use)
            .ok_or(0u64)?;

        if in_use {
            let vmsa = &guard[index];

            let target_cpu = PERCPU_AREAS.get_by_cpu_index(vmsa.cpu_index);
            target_cpu.clear_guest_vmsa_if_match(paddr);
        }

        Ok(guard.swap_remove(index))
    }
}

pub fn current_task() -> TaskPointer {
    this_cpu().runqueue.lock_read().current_task()
}

pub extern "C" fn cpu_idle_loop(cpu_index: usize) {
    debug_assert_eq!(cpu_index, this_cpu().get_cpu_index());

    loop {
        // Go idle
        halt();

        // If idle was explicitly requested by another task, then schedule that
        // task to execute again in case it wants to perform processing as a
        // result of the wake from idle.
        let maybe_task = this_cpu().runqueue().lock_write().wake_from_idle();
        if let Some(task) = maybe_task {
            schedule_task(task);
        }

        // Execute any tasks that are currently runnable.
        schedule();
    }
}
