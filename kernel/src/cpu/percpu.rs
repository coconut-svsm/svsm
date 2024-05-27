// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use super::gdt_mut;
use super::tss::{X86Tss, IST_DF};
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::ghcb::current_ghcb;
use crate::cpu::tss::TSS_LIMIT;
use crate::cpu::vmsa::init_guest_vmsa;
use crate::error::SvsmError;
use crate::locking::{LockGuard, RWLock, SpinLock};
use crate::mm::alloc::allocate_zeroed_page;
use crate::mm::pagetable::{get_init_pgtable_locked, PTEntryFlags, PageTableRef};
use crate::mm::virtualrange::VirtualRange;
use crate::mm::vm::{Mapping, VMKernelStack, VMPhysMem, VMRMapping, VMReserved, VMR};
use crate::mm::{
    virt_to_phys, SVSM_PERCPU_BASE, SVSM_PERCPU_CAA_BASE, SVSM_PERCPU_END,
    SVSM_PERCPU_TEMP_BASE_2M, SVSM_PERCPU_TEMP_BASE_4K, SVSM_PERCPU_TEMP_END_2M,
    SVSM_PERCPU_TEMP_END_4K, SVSM_PERCPU_VMSA_BASE, SVSM_STACKS_INIT_TASK, SVSM_STACK_IST_DF_BASE,
};
use crate::platform::SvsmPlatform;
use crate::sev::ghcb::{GhcbPage, GHCB};
use crate::sev::hv_doorbell::{HVDoorbell, HVDoorbellPage};
use crate::sev::msr_protocol::{hypervisor_ghcb_features, GHCBHvFeatures};
use crate::sev::vmsa::VmsaPage;
use crate::sev::RMPFlags;
use crate::task::{schedule, schedule_task, RunQueue, Task, TaskPointer, WaitQueue};
use crate::types::{PAGE_SHIFT, PAGE_SHIFT_2M, PAGE_SIZE, PAGE_SIZE_2M, SVSM_TR_FLAGS, SVSM_TSS};
use crate::utils::MemoryRegion;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::{Ref, RefCell, RefMut, UnsafeCell};
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use cpuarch::vmsa::{VMSASegment, VMSA};

#[derive(Debug)]
struct PerCpuInfo {
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

#[derive(Debug)]
struct IstStacks {
    double_fault_stack: Option<VirtAddr>,
}

impl IstStacks {
    const fn new() -> Self {
        IstStacks {
            double_fault_stack: None,
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
    guest_vmsa: SpinLock<GuestVmsaRef>,
    online: AtomicBool,
}

impl PerCpuShared {
    fn new() -> Self {
        PerCpuShared {
            guest_vmsa: SpinLock::new(GuestVmsaRef::new()),
            online: AtomicBool::new(false),
        }
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
}

#[derive(Debug)]
pub struct PerCpuUnsafe {
    shared: PerCpuShared,
    private: RefCell<PerCpu>,
    ghcb: Option<GhcbPage>,
    hv_doorbell: Option<HVDoorbellPage>,
    init_stack: Option<VirtAddr>,
    ist: IstStacks,

    /// Stack boundaries of the currently running task. This is stored in
    /// [PerCpuUnsafe] because it needs lockless read access.
    current_stack: MemoryRegion<VirtAddr>,
}

impl PerCpuUnsafe {
    pub fn new(apic_id: u32, cpu_unsafe_ptr: *mut PerCpuUnsafe) -> Self {
        Self {
            private: RefCell::new(PerCpu::new(apic_id, cpu_unsafe_ptr)),
            shared: PerCpuShared::new(),
            ghcb: None,
            hv_doorbell: None,
            init_stack: None,
            ist: IstStacks::new(),
            current_stack: MemoryRegion::new(VirtAddr::null(), 0),
        }
    }

    pub fn alloc(apic_id: u32) -> Result<*mut PerCpuUnsafe, SvsmError> {
        let vaddr = allocate_zeroed_page()?;
        unsafe {
            // Within each CPU state page, the first portion is the private
            // mutable state and remainder is the shared state.
            let unsafe_size = size_of::<PerCpuUnsafe>();
            let private_size = size_of::<PerCpu>();
            if unsafe_size + private_size > PAGE_SIZE {
                panic!("Per-CPU data is larger than one page!");
            }
            let percpu_unsafe = vaddr.as_mut_ptr::<PerCpuUnsafe>();

            (*percpu_unsafe) = PerCpuUnsafe::new(apic_id, percpu_unsafe);

            PERCPU_AREAS.push(PerCpuInfo::new(apic_id, &(*percpu_unsafe).shared));
            Ok(percpu_unsafe)
        }
    }

    pub fn shared(&self) -> &PerCpuShared {
        &self.shared
    }

    pub fn cpu(&self) -> Ref<'_, PerCpu> {
        self.private.borrow()
    }

    pub fn cpu_mut(&self) -> RefMut<'_, PerCpu> {
        self.private.borrow_mut()
    }

    pub fn setup_ghcb(&mut self) -> Result<(), SvsmError> {
        self.ghcb = Some(GhcbPage::new()?);
        Ok(())
    }

    pub fn ghcb_unsafe(&self) -> *const GHCB {
        self.ghcb
            .as_ref()
            .map(|g| g.as_ptr())
            .unwrap_or(ptr::null())
    }

    pub fn hv_doorbell(&self) -> Option<&HVDoorbell> {
        self.hv_doorbell.as_deref()
    }

    pub fn hv_doorbell_percpu_addr(&self) -> VirtAddr {
        self.hv_doorbell
            .as_ref()
            .map(|hv| ptr::from_ref(hv).into())
            .unwrap_or(VirtAddr::null())
    }

    pub fn get_top_of_stack(&self) -> VirtAddr {
        self.init_stack.unwrap()
    }

    pub fn get_top_of_df_stack(&self) -> VirtAddr {
        self.ist.double_fault_stack.unwrap()
    }

    pub fn get_current_stack(&self) -> MemoryRegion<VirtAddr> {
        self.current_stack
    }
}

#[derive(Debug)]
pub struct PerCpu {
    cpu_unsafe: *mut PerCpuUnsafe,
    apic_id: u32,
    pgtbl: SpinLock<PageTableRef>,
    tss: X86Tss,
    svsm_vmsa: Option<VmsaPage>,
    reset_ip: u64,

    /// PerCpu Virtual Memory Range
    vm_range: VMR,

    /// Address allocator for per-cpu 4k temporary mappings
    pub vrange_4k: VirtualRange,
    /// Address allocator for per-cpu 2m temporary mappings
    pub vrange_2m: VirtualRange,

    /// Task list that has been assigned for scheduling on this CPU
    runqueue: RWLock<RunQueue>,

    /// WaitQueue for request processing
    request_waitqueue: WaitQueue,
}

impl PerCpu {
    fn new(apic_id: u32, cpu_unsafe: *mut PerCpuUnsafe) -> Self {
        PerCpu {
            cpu_unsafe,
            apic_id,
            pgtbl: SpinLock::<PageTableRef>::new(PageTableRef::unset()),
            tss: X86Tss::new(),
            svsm_vmsa: None,
            reset_ip: 0xffff_fff0u64,
            vm_range: VMR::new(SVSM_PERCPU_BASE, SVSM_PERCPU_END, PTEntryFlags::GLOBAL),
            vrange_4k: VirtualRange::new(),
            vrange_2m: VirtualRange::new(),
            runqueue: RWLock::new(RunQueue::new()),
            request_waitqueue: WaitQueue::new(),
        }
    }

    pub fn alloc(apic_id: u32) -> Result<RefMut<'static, PerCpu>, SvsmError> {
        unsafe {
            let percpu_unsafe = PerCpuUnsafe::alloc(apic_id)?;
            Ok((*percpu_unsafe).cpu_mut())
        }
    }

    pub fn cpu_unsafe(&self) -> *const PerCpuUnsafe {
        self.cpu_unsafe
    }

    fn shared(&self) -> &'static PerCpuShared {
        unsafe { (*self.cpu_unsafe).shared() }
    }

    pub const fn get_apic_id(&self) -> u32 {
        self.apic_id
    }

    fn allocate_page_table(&self) -> Result<(), SvsmError> {
        self.vm_range.initialize()?;
        let pgtable_ref = get_init_pgtable_locked().clone_shared()?;
        self.set_pgtable(pgtable_ref);

        Ok(())
    }

    pub fn set_pgtable(&self, pgtable: PageTableRef) {
        let mut my_pgtable = self.get_pgtable();
        *my_pgtable = pgtable;
    }

    fn allocate_stack(&self, base: VirtAddr) -> Result<VirtAddr, SvsmError> {
        let stack = VMKernelStack::new()?;
        let top_of_stack = stack.top_of_stack(base);
        let mapping = Arc::new(Mapping::new(stack));

        self.vm_range.insert_at(base, mapping)?;

        Ok(top_of_stack)
    }

    fn allocate_init_stack(&mut self) -> Result<(), SvsmError> {
        let init_stack = Some(self.allocate_stack(SVSM_STACKS_INIT_TASK)?);
        unsafe {
            (*self.cpu_unsafe).init_stack = init_stack;
        }
        Ok(())
    }

    fn allocate_ist_stacks(&mut self) -> Result<(), SvsmError> {
        let double_fault_stack = Some(self.allocate_stack(SVSM_STACK_IST_DF_BASE)?);
        unsafe {
            (*self.cpu_unsafe).ist.double_fault_stack = double_fault_stack;
        }
        Ok(())
    }

    pub fn get_pgtable(&self) -> LockGuard<'_, PageTableRef> {
        self.pgtbl.lock()
    }

    pub fn setup_ghcb(&mut self) -> Result<(), SvsmError> {
        unsafe { (*self.cpu_unsafe).setup_ghcb() }
    }

    pub fn register_ghcb(&self) -> Result<(), SvsmError> {
        unsafe {
            let ghcb = (*self.cpu_unsafe).ghcb_unsafe();
            ghcb.as_ref().unwrap().register()
        }
    }

    pub fn setup_hv_doorbell(&mut self) -> Result<(), SvsmError> {
        let ghcb = current_ghcb();
        let page = HVDoorbellPage::new(ghcb)?;
        unsafe {
            (*self.cpu_unsafe).hv_doorbell = Some(page);
        }
        Ok(())
    }

    pub fn configure_hv_doorbell(&mut self) -> Result<(), SvsmError> {
        // #HV doorbell configuration is only required if this system will make
        // use of restricted injection.
        if hypervisor_ghcb_features().contains(GHCBHvFeatures::SEV_SNP_RESTR_INJ) {
            self.setup_hv_doorbell()?;
        }
        Ok(())
    }

    fn setup_tss(&mut self) {
        let double_fault_stack = unsafe { (*self.cpu_unsafe).get_top_of_df_stack() };
        self.tss.ist_stacks[IST_DF] = double_fault_stack;
    }

    pub fn map_self_stage2(&self) -> Result<(), SvsmError> {
        let vaddr = VirtAddr::from(self.cpu_unsafe);
        let paddr = virt_to_phys(vaddr);
        let flags = PTEntryFlags::data();

        self.get_pgtable().map_4k(SVSM_PERCPU_BASE, paddr, flags)
    }

    pub fn map_self(&self) -> Result<(), SvsmError> {
        let vaddr = VirtAddr::from(self.cpu_unsafe);
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

    pub fn setup(&mut self, platform: &dyn SvsmPlatform) -> Result<(), SvsmError> {
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
    pub fn setup_on_cpu(&mut self, platform: &dyn SvsmPlatform) -> Result<(), SvsmError> {
        platform.setup_percpu_current(self)
    }

    pub fn setup_idle_task(&mut self, entry: extern "C" fn()) -> Result<(), SvsmError> {
        let idle_task = Task::create(self, entry)?;
        self.runqueue.lock_read().set_idle_task(idle_task);
        Ok(())
    }

    pub fn load_pgtable(&self) {
        self.get_pgtable().load();
    }

    // Ensure this function does not have multiple concurrent callers.
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub fn load_tss(&mut self) {
        gdt_mut().load_tss(&self.tss);
    }

    pub fn load(&mut self) {
        self.load_pgtable();
        self.load_tss();
    }

    pub fn shutdown(&mut self) -> Result<(), SvsmError> {
        unsafe {
            let ghcb = (*self.cpu_unsafe).ghcb_unsafe();
            if ghcb.is_null() {
                return Ok(());
            }

            (*ghcb).shutdown()
        }
    }

    pub fn set_reset_ip(&mut self, reset_ip: u64) {
        self.reset_ip = reset_ip;
    }

    pub fn alloc_svsm_vmsa(&mut self) -> Result<&mut VmsaPage, SvsmError> {
        if self.svsm_vmsa.is_some() {
            // FIXME: add a more explicit error variant for this condition
            return Err(SvsmError::Mem);
        }

        let vmsa = VmsaPage::new(RMPFlags::GUEST_VMPL)?;
        Ok(self.svsm_vmsa.insert(vmsa))
    }

    pub fn prepare_svsm_vmsa(&mut self, start_rip: u64) -> Option<&mut VmsaPage> {
        let top_of_stack = unsafe { (*self.cpu_unsafe).get_top_of_stack() };
        let tr = self.vmsa_tr_segment();
        let cr3 = self.get_pgtable().cr3_value();

        let vmsa = self.svsm_vmsa.as_mut()?;
        vmsa.tr = tr;
        vmsa.rip = start_rip;
        vmsa.rsp = top_of_stack.into();
        vmsa.cr3 = cr3.into();
        Some(vmsa)
    }

    pub fn unmap_guest_vmsa(&self) {
        assert!(self.apic_id == this_cpu().get_apic_id());
        // Ignore errors - the mapping might or might not be there
        let _ = self.vm_range.remove(SVSM_PERCPU_VMSA_BASE);
    }

    pub fn map_guest_vmsa(&self, paddr: PhysAddr) -> Result<(), SvsmError> {
        assert!(self.apic_id == this_cpu().get_apic_id());
        let vmsa_mapping = Arc::new(VMPhysMem::new_mapping(paddr, PAGE_SIZE, true));
        self.vm_range
            .insert_at(SVSM_PERCPU_VMSA_BASE, vmsa_mapping)?;

        Ok(())
    }

    pub fn guest_vmsa_ref(&self) -> LockGuard<'_, GuestVmsaRef> {
        self.shared().guest_vmsa.lock()
    }

    pub fn alloc_guest_vmsa(&self) -> Result<(), SvsmError> {
        let mut vmsa = VmsaPage::new(RMPFlags::GUEST_VMPL)?;
        let paddr = vmsa.paddr();
        init_guest_vmsa(&mut vmsa, self.reset_ip);

        // Ensure the new VMSA does not get freed when we leave this
        // function.
        let _ = VmsaPage::leak(vmsa);

        self.shared().update_guest_vmsa(paddr);

        Ok(())
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

    fn vmsa_tr_segment(&self) -> VMSASegment {
        VMSASegment {
            selector: SVSM_TSS,
            flags: SVSM_TR_FLAGS,
            limit: TSS_LIMIT as u32,
            base: ptr::addr_of!(self.tss) as u64,
        }
    }

    pub fn virt_range_init(&mut self) {
        // Initialize 4k range
        let page_count = (SVSM_PERCPU_TEMP_END_4K - SVSM_PERCPU_TEMP_BASE_4K) / PAGE_SIZE;
        assert!(page_count <= VirtualRange::CAPACITY);
        self.vrange_4k
            .init(SVSM_PERCPU_TEMP_BASE_4K, page_count, PAGE_SHIFT);

        // Initialize 2M range
        let page_count = (SVSM_PERCPU_TEMP_END_2M - SVSM_PERCPU_TEMP_BASE_2M) / PAGE_SIZE_2M;
        assert!(page_count <= VirtualRange::CAPACITY);
        self.vrange_2m
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
    pub fn new_mapping(&mut self, mapping: Arc<Mapping>) -> Result<VMRMapping<'_>, SvsmError> {
        VMRMapping::new(&mut self.vm_range, mapping)
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

    pub fn schedule_init(&mut self) -> TaskPointer {
        let task = self.runqueue.lock_write().schedule_init();
        unsafe {
            (*self.cpu_unsafe).current_stack = task.stack_bounds();
        }
        task
    }

    pub fn schedule_prepare(&mut self) -> Option<(TaskPointer, TaskPointer)> {
        let ret = self.runqueue.lock_write().schedule_prepare();
        if let Some((_, ref next)) = ret {
            unsafe {
                (*self.cpu_unsafe).current_stack = next.stack_bounds();
            }
        };
        ret
    }

    pub fn runqueue(&self) -> &RWLock<RunQueue> {
        &self.runqueue
    }

    pub fn current_task(&self) -> TaskPointer {
        self.runqueue.lock_read().current_task()
    }

    pub fn set_tss_rsp0(&mut self, addr: VirtAddr) {
        self.tss.stacks[0] = addr;
    }
}

pub fn this_cpu_unsafe() -> *mut PerCpuUnsafe {
    SVSM_PERCPU_BASE.as_mut_ptr::<PerCpuUnsafe>()
}

pub fn this_cpu_shared() -> &'static PerCpuShared {
    unsafe { (*this_cpu_unsafe()).shared() }
}

pub fn this_cpu() -> Ref<'static, PerCpu> {
    let cpu_unsafe = unsafe { &*this_cpu_unsafe() };
    cpu_unsafe.cpu()
}

pub fn this_cpu_mut() -> RefMut<'static, PerCpu> {
    let cpu_unsafe = unsafe { &*this_cpu_unsafe() };
    cpu_unsafe.cpu_mut()
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
    this_cpu_mut()
        .request_waitqueue
        .wait_for_event(current_task);
    schedule();
}

pub fn process_requests() {
    let maybe_task = this_cpu_mut().request_waitqueue.wakeup();
    if let Some(task) = maybe_task {
        schedule_task(task);
    }
}

pub fn current_task() -> TaskPointer {
    this_cpu().runqueue.lock_read().current_task()
}
