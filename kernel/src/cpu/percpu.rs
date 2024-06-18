// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use super::gdt_mut;
use super::tss::{X86Tss, IST_DF};
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::apic::ApicError;
use crate::cpu::idt::common::INT_INJ_VECTOR;
use crate::cpu::tss::TSS_LIMIT;
use crate::cpu::vmsa::init_guest_vmsa;
use crate::cpu::vmsa::vmsa_mut_ref_from_vaddr;
use crate::cpu::LocalApic;
use crate::error::SvsmError;
use crate::locking::{LockGuard, RWLock, SpinLock};
use crate::mm::alloc::{allocate_zeroed_page, free_page};
use crate::mm::pagetable::{get_init_pgtable_locked, PTEntryFlags, PageTableRef};
use crate::mm::virtualrange::VirtualRange;
use crate::mm::vm::{Mapping, VMKernelStack, VMPhysMem, VMRMapping, VMReserved, VMR};
use crate::mm::{
    virt_to_phys, SVSM_PERCPU_BASE, SVSM_PERCPU_CAA_BASE, SVSM_PERCPU_END,
    SVSM_PERCPU_TEMP_BASE_2M, SVSM_PERCPU_TEMP_BASE_4K, SVSM_PERCPU_TEMP_END_2M,
    SVSM_PERCPU_TEMP_END_4K, SVSM_PERCPU_VMSA_BASE, SVSM_STACKS_INIT_TASK, SVSM_STACK_IST_DF_BASE,
};
use crate::platform::{SvsmPlatform, SVSM_PLATFORM};
use crate::sev::ghcb::GHCB;
use crate::sev::hv_doorbell::HVDoorbell;
use crate::sev::msr_protocol::{hypervisor_ghcb_features, GHCBHvFeatures};
use crate::sev::utils::RMPFlags;
use crate::sev::vmsa::allocate_new_vmsa;
use crate::task::{schedule, schedule_task, RunQueue, Task, TaskPointer, WaitQueue};
use crate::types::{PAGE_SHIFT, PAGE_SHIFT_2M, PAGE_SIZE, PAGE_SIZE_2M, SVSM_TR_FLAGS, SVSM_TSS};
use crate::utils::MemoryRegion;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::{Cell, Ref, RefCell, RefMut, UnsafeCell};
use core::mem::size_of;
use core::ptr;
use core::slice::Iter;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use cpuarch::vmsa::{VMSASegment, VMSA};

#[derive(Copy, Clone, Debug)]
pub struct PerCpuInfo {
    apic_id: u32,
    cpu_shared: &'static PerCpuShared,
}

impl PerCpuInfo {
    const fn new(apic_id: u32, cpu_shared: &'static PerCpuShared) -> Self {
        Self {
            apic_id,
            cpu_shared,
        }
    }

    pub fn unwrap(&self) -> &'static PerCpuShared {
        self.cpu_shared
    }
}

// PERCPU areas virtual addresses into shared memory
pub static PERCPU_AREAS: PerCpuAreas = PerCpuAreas::new();

// We use an UnsafeCell to allow for a static with interior
// mutability. Normally, we would need to guarantee synchronization
// on the backing datatype, but this is not needed because writes to
// the structure only occur at initialization, from CPU 0, and reads
// should only occur after all writes are done.
#[derive(Debug)]
pub struct PerCpuAreas {
    areas: UnsafeCell<Vec<PerCpuInfo>>,
}

unsafe impl Sync for PerCpuAreas {}

impl PerCpuAreas {
    const fn new() -> Self {
        Self {
            areas: UnsafeCell::new(Vec::new()),
        }
    }

    unsafe fn push(&self, info: PerCpuInfo) {
        let ptr = self.areas.get().as_mut().unwrap();
        ptr.push(info);
    }

    pub fn iter(&self) -> Iter<'_, PerCpuInfo> {
        let ptr = unsafe { self.areas.get().as_ref().unwrap() };
        ptr.iter()
    }

    // Fails if no such area exists or its address is NULL
    pub fn get(&self, apic_id: u32) -> Option<&'static PerCpuShared> {
        // For this to not produce UB the only invariant we must
        // uphold is that there are no mutations or mutable aliases
        // going on when casting via as_ref(). This only happens via
        // Self::push(), which is intentionally unsafe and private.
        let ptr = unsafe { self.areas.get().as_ref().unwrap() };
        ptr.iter()
            .find(|info| info.apic_id == apic_id)
            .map(|info| info.cpu_shared)
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct VmsaRef {
    pub vaddr: VirtAddr,
    pub paddr: PhysAddr,
    pub guest_owned: bool,
}

impl VmsaRef {
    const fn new(v: VirtAddr, p: PhysAddr, g: bool) -> Self {
        VmsaRef {
            vaddr: v,
            paddr: p,
            guest_owned: g,
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn vmsa(&mut self) -> &mut VMSA {
        let ptr = self.vaddr.as_mut_ptr::<VMSA>();
        // SAFETY: this function takes &mut self, so only one mutable
        // reference to the underlying VMSA can exist.
        unsafe { ptr.as_mut().unwrap() }
    }
}

#[derive(Debug)]
struct IstStacks {
    double_fault_stack: Cell<Option<VirtAddr>>,
}

impl IstStacks {
    const fn new() -> Self {
        IstStacks {
            double_fault_stack: Cell::new(None),
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

    #[allow(clippy::needless_pass_by_ref_mut)]
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
    guest_vmsa: SpinLock<GuestVmsaRef>,
    online: AtomicBool,
    ipi_irr: [AtomicU32; 8],
    ipi_pending: AtomicBool,
    nmi_pending: AtomicBool,
}

impl PerCpuShared {
    fn new(apic_id: u32) -> Self {
        PerCpuShared {
            apic_id,
            guest_vmsa: SpinLock::new(GuestVmsaRef::new()),
            online: AtomicBool::new(false),
            ipi_irr: [
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
            ],
            ipi_pending: AtomicBool::new(false),
            nmi_pending: AtomicBool::new(false),
        }
    }

    pub const fn apic_id(&self) -> u32 {
        self.apic_id
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
}

const _: () = assert!(size_of::<PerCpu>() <= PAGE_SIZE);

#[derive(Debug)]
pub struct PerCpu {
    shared: PerCpuShared,

    pgtbl: RefCell<PageTableRef>,
    tss: Cell<X86Tss>,
    svsm_vmsa: Cell<Option<VmsaRef>>,
    reset_ip: Cell<u64>,
    /// PerCpu Virtual Memory Range
    vm_range: VMR,
    /// Address allocator for per-cpu 4k temporary mappings
    pub vrange_4k: RefCell<VirtualRange>,
    /// Address allocator for per-cpu 2m temporary mappings
    pub vrange_2m: RefCell<VirtualRange>,
    /// Task list that has been assigned for scheduling on this CPU
    runqueue: RefCell<RunQueue>,
    /// WaitQueue for request processing
    request_waitqueue: RefCell<WaitQueue>,
    /// Local APIC state for APIC emulation
    apic: RefCell<Option<LocalApic>>,

    ghcb: Cell<Option<&'static GHCB>>,
    hv_doorbell: Cell<*const HVDoorbell>,
    init_stack: Cell<Option<VirtAddr>>,
    ist: IstStacks,

    /// Stack boundaries of the currently running task.
    current_stack: Cell<MemoryRegion<VirtAddr>>,
}

impl PerCpu {
    fn new(apic_id: u32) -> Self {
        Self {
            pgtbl: RefCell::new(PageTableRef::unset()),
            tss: Cell::new(X86Tss::new()),
            svsm_vmsa: Cell::new(None),
            reset_ip: Cell::new(0xffff_fff0),
            vm_range: VMR::new(SVSM_PERCPU_BASE, SVSM_PERCPU_END, PTEntryFlags::GLOBAL),
            vrange_4k: RefCell::new(VirtualRange::new()),
            vrange_2m: RefCell::new(VirtualRange::new()),
            runqueue: RefCell::new(RunQueue::new()),
            request_waitqueue: RefCell::new(WaitQueue::new()),
            apic: RefCell::new(None),

            shared: PerCpuShared::new(apic_id),
            ghcb: Cell::new(None),
            hv_doorbell: Cell::new(ptr::null()),
            init_stack: Cell::new(None),
            ist: IstStacks::new(),
            current_stack: Cell::new(MemoryRegion::new(VirtAddr::null(), 0)),
        }
    }

    pub fn alloc(apic_id: u32) -> Result<&'static Self, SvsmError> {
        let vaddr = allocate_zeroed_page()?;
        let percpu_ptr = vaddr.as_mut_ptr::<Self>();
        unsafe {
            (*percpu_ptr) = Self::new(apic_id);
            let percpu = &*percpu_ptr;
            PERCPU_AREAS.push(PerCpuInfo::new(apic_id, &percpu.shared));
            Ok(percpu)
        }
    }

    pub fn shared(&self) -> &PerCpuShared {
        &self.shared
    }

    pub fn setup_ghcb(&self) -> Result<(), SvsmError> {
        let ghcb_page = allocate_zeroed_page()?;
        if let Err(e) = GHCB::init(ghcb_page) {
            free_page(ghcb_page);
            return Err(e);
        };
        let ghcb = unsafe { &*ghcb_page.as_ptr() };
        self.ghcb.set(Some(ghcb));
        Ok(())
    }

    fn ghcb(&self) -> Option<&'static GHCB> {
        self.ghcb.get()
    }

    pub fn hv_doorbell_unsafe(&self) -> *const HVDoorbell {
        self.hv_doorbell.get()
    }

    pub fn hv_doorbell_addr(&self) -> usize {
        ptr::addr_of!(self.hv_doorbell) as usize
    }

    pub fn get_top_of_stack(&self) -> VirtAddr {
        self.init_stack.get().unwrap()
    }

    pub fn get_top_of_df_stack(&self) -> VirtAddr {
        self.ist.double_fault_stack.get().unwrap()
    }

    pub fn get_current_stack(&self) -> MemoryRegion<VirtAddr> {
        self.current_stack.get()
    }

    pub fn get_apic_id(&self) -> u32 {
        self.shared().apic_id()
    }

    fn allocate_page_table(&self) -> Result<(), SvsmError> {
        self.vm_range.initialize()?;
        let pgtable_ref = get_init_pgtable_locked().clone_shared()?;
        self.set_pgtable(pgtable_ref);

        Ok(())
    }

    pub fn set_pgtable(&self, pgtable: PageTableRef) {
        *self.get_pgtable() = pgtable;
    }

    fn allocate_stack(&self, base: VirtAddr) -> Result<VirtAddr, SvsmError> {
        let stack = VMKernelStack::new()?;
        let top_of_stack = stack.top_of_stack(base);
        let mapping = Arc::new(Mapping::new(stack));

        self.vm_range.insert_at(base, mapping)?;

        Ok(top_of_stack)
    }

    fn allocate_init_stack(&self) -> Result<(), SvsmError> {
        let init_stack = Some(self.allocate_stack(SVSM_STACKS_INIT_TASK)?);
        self.init_stack.set(init_stack);
        Ok(())
    }

    fn allocate_ist_stacks(&self) -> Result<(), SvsmError> {
        let double_fault_stack = self.allocate_stack(SVSM_STACK_IST_DF_BASE)?;
        self.ist.double_fault_stack.set(Some(double_fault_stack));
        Ok(())
    }

    pub fn get_pgtable(&self) -> RefMut<'_, PageTableRef> {
        self.pgtbl.borrow_mut()
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
        let vaddr = allocate_zeroed_page()?;
        let ghcb = current_ghcb();
        if let Err(e) = HVDoorbell::init(vaddr, ghcb) {
            free_page(vaddr);
            return Err(e);
        }

        self.hv_doorbell.set(vaddr.as_mut_ptr());
        Ok(())
    }

    pub fn configure_hv_doorbell(&self) -> Result<(), SvsmError> {
        // #HV doorbell configuration is only required if this system will make
        // use of restricted injection.
        if hypervisor_ghcb_features().contains(GHCBHvFeatures::SEV_SNP_RESTR_INJ) {
            self.setup_hv_doorbell()?;
        }
        Ok(())
    }

    pub fn hv_doorbell(&self) -> Option<&'static HVDoorbell> {
        unsafe {
            let hv_doorbell = self.hv_doorbell.get();
            if hv_doorbell.is_null() {
                None
            } else {
                // The HV doorbell page can only ever be borrowed shared, never
                // mutable, and can safely have a static lifetime.
                Some(&*hv_doorbell)
            }
        }
    }

    fn setup_tss(&self) {
        let double_fault_stack = self.get_top_of_df_stack();
        let mut tss = self.tss.get();
        tss.ist_stacks[IST_DF] = double_fault_stack;
        self.tss.set(tss);
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

    pub fn setup(&self, platform: &dyn SvsmPlatform) -> Result<(), SvsmError> {
        // Allocate page-table
        self.allocate_page_table()?;

        // Map PerCpu data in own page-table
        self.map_self()?;

        // Reserve ranges for temporary mappings
        self.initialize_vm_ranges()?;

        // Allocate per-cpu init stack
        self.allocate_init_stack()?;

        // Allocate IST stacks
        self.allocate_ist_stacks()?;

        // Setup TSS
        self.setup_tss();

        // Initialize allocator for temporary mappings
        self.virt_range_init();

        self.finish_page_table();

        // Complete platform-specific initialization.
        platform.setup_percpu(self)?;

        Ok(())
    }

    // Setup code which needs to run on the target CPU
    pub fn setup_on_cpu(&self, platform: &dyn SvsmPlatform) -> Result<(), SvsmError> {
        platform.setup_percpu_current(self)
    }

    pub fn setup_idle_task(&self, entry: extern "C" fn()) -> Result<(), SvsmError> {
        let idle_task = Task::create(self, entry)?;
        self.runqueue.borrow().set_idle_task(idle_task);
        Ok(())
    }

    pub fn load_pgtable(&self) {
        self.get_pgtable().load();
    }

    pub fn load_tss(&self) {
        // SAFETY: this can only produce UB if someone else calls self.tss.set
        // () while this new reference is alive, which cannot happen as this
        // data is local to this CPU. We need to get a reference to the value
        // inside the Cell because the address of the TSS will be used. If we
        // did self.tss.get(), then the address of a temporary copy would be
        // used.
        let tss = unsafe { &*self.tss.as_ptr() };
        gdt_mut().load_tss(tss);
    }

    pub fn load(&self) {
        self.load_pgtable();
        self.load_tss();
    }

    pub fn shutdown(&self) -> Result<(), SvsmError> {
        if let Some(ghcb) = self.ghcb.get() {
            ghcb.shutdown()?;
        }
        Ok(())
    }

    pub fn set_reset_ip(&self, reset_ip: u64) {
        self.reset_ip.set(reset_ip);
    }

    pub fn alloc_svsm_vmsa(&self) -> Result<VmsaRef, SvsmError> {
        if self.svsm_vmsa.get().is_some() {
            // FIXME: add a more explicit error variant for this condition
            return Err(SvsmError::Mem);
        }

        let vaddr = allocate_new_vmsa(RMPFlags::GUEST_VMPL)?;
        let paddr = virt_to_phys(vaddr);

        let vmsa = VmsaRef::new(vaddr, paddr, false);
        self.svsm_vmsa.set(Some(vmsa));

        Ok(vmsa)
    }

    pub fn prepare_svsm_vmsa(&self, start_rip: u64) {
        let mut vmsa = self.svsm_vmsa.get().unwrap();
        let vmsa_ref = vmsa.vmsa();

        vmsa_ref.tr = self.vmsa_tr_segment();
        vmsa_ref.rip = start_rip;
        let top_of_stack = self.get_top_of_stack();
        vmsa_ref.rsp = top_of_stack.into();
        vmsa_ref.cr3 = self.get_pgtable().cr3_value().into();
    }

    pub fn unmap_guest_vmsa(&self) {
        assert!(self.shared().apic_id == this_cpu().get_apic_id());
        // Ignore errors - the mapping might or might not be there
        let _ = self.vm_range.remove(SVSM_PERCPU_VMSA_BASE);
    }

    pub fn map_guest_vmsa(&self, paddr: PhysAddr) -> Result<(), SvsmError> {
        assert!(self.shared().apic_id == this_cpu().get_apic_id());
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
        if SVSM_PLATFORM.as_dyn_ref().use_alternate_injection() {
            *self.apic.borrow_mut() = Some(LocalApic::new());

            // Configure the interrupt injection vector.
            let ghcb = self.ghcb().unwrap();
            ghcb.configure_interrupt_injection(INT_INJ_VECTOR)?;
        }

        let vaddr = allocate_new_vmsa(RMPFlags::GUEST_VMPL)?;
        let paddr = virt_to_phys(vaddr);

        let vmsa = vmsa_mut_ref_from_vaddr(vaddr);
        init_guest_vmsa(vmsa, self.reset_ip.get(), self.apic.borrow().is_some());

        self.shared().update_guest_vmsa(paddr);

        Ok(())
    }

    /// Returns a shared reference to the local APIC, or `None` if APIC
    /// emulation is not enabled.
    pub fn apic(&self) -> Option<Ref<'_, LocalApic>> {
        let apic = self.apic.borrow();
        Ref::filter_map(apic, Option::as_ref).ok()
    }

    /// Returns a mutable reference to the local APIC, or `None` if APIC
    /// emulation is not enabled.
    pub fn apic_mut(&self) -> Option<RefMut<'_, LocalApic>> {
        let apic = self.apic.borrow_mut();
        RefMut::filter_map(apic, Option::as_mut).ok()
    }

    pub fn unmap_caa(&self) {
        // Ignore errors - the mapping might or might not be there
        let _ = self.vm_range.remove(SVSM_PERCPU_CAA_BASE);
    }

    pub fn map_guest_caa(&self, paddr: PhysAddr) -> Result<(), SvsmError> {
        self.unmap_caa();

        let caa_mapping = Arc::new(VMPhysMem::new_mapping(paddr, PAGE_SIZE, true));
        self.vm_range.insert_at(SVSM_PERCPU_CAA_BASE, caa_mapping)?;

        Ok(())
    }

    pub fn disable_apic_emulation(&self) -> Result<(), SvsmError> {
        if let Some(mut apic) = self.apic_mut() {
            // APIC emulation cannot be disabled if the platform has locked
            // the use of APIC emulation.
            SVSM_PLATFORM.as_dyn_ref().disable_apic_emulation()?;
            let mut vmsa_ref = self.guest_vmsa_ref();
            let caa_addr = vmsa_ref.caa_addr();
            let vmsa = vmsa_ref.vmsa();
            apic.disable_apic_emulation(vmsa, caa_addr);
        }
        let _ = self.apic.borrow_mut().take();
        Ok(())
    }

    pub fn clear_pending_interrupts(&self) {
        if let Some(mut apic) = self.apic_mut() {
            let mut vmsa_ref = self.guest_vmsa_ref();
            let caa_addr = vmsa_ref.caa_addr();
            let vmsa = vmsa_ref.vmsa();
            apic.check_delivered_interrupts(vmsa, caa_addr);
        }
    }

    pub fn update_apic_emulation(&self, vmsa: &mut VMSA, caa_addr: Option<VirtAddr>) {
        if let Some(mut apic) = self.apic_mut() {
            apic.present_interrupts(self.shared(), vmsa, caa_addr);
        }
    }

    pub fn read_apic_register(&self, register: u64) -> Option<Result<u64, ApicError>> {
        let mut apic = self.apic_mut()?;
        let mut vmsa_ref = self.guest_vmsa_ref();
        let caa_addr = vmsa_ref.caa_addr();
        let vmsa = vmsa_ref.vmsa();
        Some(apic.read_register(self.shared(), vmsa, caa_addr, register))
    }

    pub fn write_apic_register(&self, register: u64, value: u64) -> Option<Result<(), ApicError>> {
        let mut apic = self.apic_mut()?;
        let mut vmsa_ref = self.guest_vmsa_ref();
        let caa_addr = vmsa_ref.caa_addr();
        let vmsa = vmsa_ref.vmsa();
        Some(apic.write_register(vmsa, caa_addr, register, value))
    }

    fn vmsa_tr_segment(&self) -> VMSASegment {
        VMSASegment {
            selector: SVSM_TSS,
            flags: SVSM_TR_FLAGS,
            limit: TSS_LIMIT as u32,
            base: ptr::addr_of!(self.tss) as u64,
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
    pub fn populate_page_table(&self, pt: &mut PageTableRef) {
        self.vm_range.populate(pt);
    }

    pub fn handle_pf(&self, vaddr: VirtAddr, write: bool) -> Result<(), SvsmError> {
        self.vm_range.handle_page_fault(vaddr, write)
    }

    pub fn schedule_init(&self) -> TaskPointer {
        let task = self.runqueue.borrow_mut().schedule_init();
        self.current_stack.set(task.stack_bounds());
        task
    }

    pub fn schedule_prepare(&self) -> Option<(TaskPointer, TaskPointer)> {
        let ret = self.runqueue.borrow_mut().schedule_prepare();
        if let Some((_, ref next)) = ret {
            self.current_stack.set(next.stack_bounds());
        };
        ret
    }

    pub fn runqueue(&self) -> &RefCell<RunQueue> {
        &self.runqueue
    }

    pub fn current_task(&self) -> TaskPointer {
        self.runqueue.borrow().current_task()
    }

    pub fn set_tss_rsp0(&self, addr: VirtAddr) {
        let mut tss = self.tss.get();
        tss.stacks[0] = addr;
        self.tss.set(tss);
    }
}

pub fn this_cpu() -> &'static PerCpu {
    unsafe { &*SVSM_PERCPU_BASE.as_mut_ptr::<PerCpu>() }
}

pub fn this_cpu_shared() -> &'static PerCpuShared {
    this_cpu().shared()
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
    pub apic_id: u32,
    pub guest_owned: bool,
    pub in_use: bool,
}

impl VmsaRegistryEntry {
    pub const fn new(paddr: PhysAddr, apic_id: u32, guest_owned: bool) -> Self {
        VmsaRegistryEntry {
            paddr,
            apic_id,
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

    pub fn register(
        &self,
        paddr: PhysAddr,
        apic_id: u32,
        guest_owned: bool,
    ) -> Result<(), SvsmError> {
        let mut guard = self.vmsas.lock_write();
        if guard.iter().any(|vmsa| vmsa.paddr == paddr) {
            return Err(SvsmError::InvalidAddress);
        }

        guard.push(VmsaRegistryEntry::new(paddr, apic_id, guest_owned));
        Ok(())
    }

    pub fn set_used(&self, paddr: PhysAddr) -> Option<u32> {
        self.vmsas
            .lock_write()
            .iter_mut()
            .find(|vmsa| vmsa.paddr == paddr && !vmsa.in_use)
            .map(|vmsa| {
                vmsa.in_use = true;
                vmsa.apic_id
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

            if vmsa.apic_id == 0 {
                return Err(0);
            }

            let target_cpu = PERCPU_AREAS
                .get(vmsa.apic_id)
                .expect("Invalid APIC-ID in VMSA registry");
            target_cpu.clear_guest_vmsa_if_match(paddr);
        }

        Ok(guard.swap_remove(index))
    }
}

pub fn wait_for_requests() {
    let current_task = current_task();
    this_cpu()
        .request_waitqueue
        .borrow_mut()
        .wait_for_event(current_task);
    schedule();
}

pub fn process_requests() {
    let maybe_task = this_cpu().request_waitqueue.borrow_mut().wakeup();
    if let Some(task) = maybe_task {
        schedule_task(task);
    }
}

pub fn current_task() -> TaskPointer {
    this_cpu().runqueue.borrow().current_task()
}
