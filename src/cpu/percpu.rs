// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use super::gdt_mut;
use super::tss::{X86Tss, IST_DF};
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::tss::TSS_LIMIT;
use crate::cpu::vmsa::init_guest_vmsa;
use crate::cpu::vmsa::vmsa_mut_ref_from_vaddr;
use crate::error::SvsmError;
use crate::locking::{LockGuard, RWLock, SpinLock};
use crate::mm::alloc::{allocate_page, allocate_zeroed_page};
use crate::mm::pagetable::{get_init_pgtable_locked, PTEntryFlags, PageTableRef};
use crate::mm::virtualrange::VirtualRange;
use crate::mm::vm::{Mapping, VMKernelStack, VMPhysMem, VMRMapping, VMReserved, VMR};
use crate::mm::{
    virt_to_phys, SVSM_PERCPU_BASE, SVSM_PERCPU_CAA_BASE, SVSM_PERCPU_END,
    SVSM_PERCPU_TEMP_BASE_2M, SVSM_PERCPU_TEMP_BASE_4K, SVSM_PERCPU_TEMP_END_2M,
    SVSM_PERCPU_TEMP_END_4K, SVSM_PERCPU_VMSA_BASE, SVSM_STACKS_INIT_TASK, SVSM_STACK_IST_DF_BASE,
};
use crate::sev::ghcb::GHCB;
use crate::sev::utils::RMPFlags;
use crate::sev::vmsa::allocate_new_vmsa;
use crate::task::RunQueue;
use crate::types::{PAGE_SHIFT, PAGE_SHIFT_2M, PAGE_SIZE, PAGE_SIZE_2M, SVSM_TR_FLAGS, SVSM_TSS};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use cpuarch::vmsa::{VMSASegment, VMSA};

#[derive(Debug)]
struct PerCpuInfo {
    apic_id: u32,
    addr: VirtAddr,
}

impl PerCpuInfo {
    const fn new(apic_id: u32, addr: VirtAddr) -> Self {
        Self { apic_id, addr }
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
        ptr.iter().find(|info| info.apic_id == apic_id).map(|info| {
            let ptr = info.addr.as_ptr::<PerCpuShared>();
            unsafe { ptr.as_ref().unwrap() }
        })
    }
}

#[derive(Copy, Clone, Debug)]
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

    pub fn vmsa(&mut self) -> &mut VMSA {
        let ptr = self.vaddr.as_mut_ptr::<VMSA>();
        unsafe { ptr.as_mut().unwrap() }
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

#[derive(Debug, Clone, Copy)]
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
}

#[derive(Debug)]
pub struct PerCpuShared {
    guest_vmsa: SpinLock<GuestVmsaRef>,
}

impl PerCpuShared {
    fn new() -> Self {
        PerCpuShared {
            guest_vmsa: SpinLock::new(GuestVmsaRef::new()),
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
}

#[derive(Debug)]
pub struct PerCpu {
    pub shared: &'static PerCpuShared,
    online: AtomicBool,
    apic_id: u32,
    pgtbl: SpinLock<PageTableRef>,
    ghcb: *mut GHCB,
    init_stack: Option<VirtAddr>,
    ist: IstStacks,
    tss: X86Tss,
    svsm_vmsa: Option<VmsaRef>,
    reset_ip: u64,

    /// PerCpu Virtual Memory Range
    vm_range: VMR,

    /// Address allocator for per-cpu 4k temporary mappings
    pub vrange_4k: VirtualRange,
    /// Address allocator for per-cpu 2m temporary mappings
    pub vrange_2m: VirtualRange,

    /// Task list that has been assigned for scheduling on this CPU
    runqueue: RWLock<RunQueue>,
}

impl PerCpu {
    fn new(apic_id: u32, shared: &'static PerCpuShared) -> Self {
        PerCpu {
            shared,
            online: AtomicBool::new(false),
            apic_id,
            pgtbl: SpinLock::<PageTableRef>::new(PageTableRef::unset()),
            ghcb: ptr::null_mut(),
            init_stack: None,
            ist: IstStacks::new(),
            tss: X86Tss::new(),
            svsm_vmsa: None,
            reset_ip: 0xffff_fff0u64,
            vm_range: VMR::new(SVSM_PERCPU_BASE, SVSM_PERCPU_END, PTEntryFlags::GLOBAL),
            vrange_4k: VirtualRange::new(),
            vrange_2m: VirtualRange::new(),
            runqueue: RWLock::new(RunQueue::new(apic_id)),
        }
    }

    pub fn alloc(apic_id: u32) -> Result<*mut PerCpu, SvsmError> {
        let vaddr = allocate_zeroed_page()?;
        unsafe {
            // Within each CPU state page, the first portion is the private
            // mutable state and remainder is the shared state.
            let private_size = size_of::<PerCpu>();
            let shared_size = size_of::<PerCpuShared>();
            if private_size + shared_size > PAGE_SIZE {
                panic!("Per-CPU data is larger than one page!");
            }

            let shared_vaddr = vaddr + private_size;
            let percpu_shared = shared_vaddr.as_mut_ptr::<PerCpuShared>();
            (*percpu_shared) = PerCpuShared::new();

            let percpu = vaddr.as_mut_ptr::<PerCpu>();
            (*percpu) = PerCpu::new(apic_id, &*percpu_shared);

            PERCPU_AREAS.push(PerCpuInfo::new(apic_id, shared_vaddr));
            Ok(percpu)
        }
    }

    pub fn set_online(&mut self) {
        self.online.store(true, Ordering::Relaxed);
    }

    pub fn is_online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    pub const fn get_apic_id(&self) -> u32 {
        self.apic_id
    }

    fn allocate_page_table(&mut self) -> Result<(), SvsmError> {
        self.vm_range.initialize()?;
        let mut pgtable_ref = get_init_pgtable_locked().clone_shared()?;
        self.vm_range.populate(&mut pgtable_ref);
        self.set_pgtable(pgtable_ref);

        Ok(())
    }

    pub fn set_pgtable(&mut self, pgtable: PageTableRef) {
        let mut my_pgtable = self.get_pgtable();
        *my_pgtable = pgtable;
    }

    fn allocate_stack(&mut self, base: VirtAddr) -> Result<VirtAddr, SvsmError> {
        let stack = VMKernelStack::new()?;
        let top_of_stack = stack.top_of_stack(base);
        let mapping = Arc::new(Mapping::new(stack));

        self.vm_range.insert_at(base, mapping)?;

        Ok(top_of_stack)
    }

    fn allocate_init_stack(&mut self) -> Result<(), SvsmError> {
        self.init_stack = Some(self.allocate_stack(SVSM_STACKS_INIT_TASK)?);
        Ok(())
    }

    fn allocate_ist_stacks(&mut self) -> Result<(), SvsmError> {
        self.ist.double_fault_stack = Some(self.allocate_stack(SVSM_STACK_IST_DF_BASE)?);
        Ok(())
    }

    pub fn get_pgtable(&self) -> LockGuard<PageTableRef> {
        self.pgtbl.lock()
    }

    pub fn setup_ghcb(&mut self) -> Result<(), SvsmError> {
        let ghcb_page = allocate_page().expect("Failed to allocate GHCB page");
        self.ghcb = ghcb_page.as_mut_ptr::<GHCB>();
        unsafe { (*self.ghcb).init() }
    }

    pub fn register_ghcb(&self) -> Result<(), SvsmError> {
        unsafe { self.ghcb.as_ref().unwrap().register() }
    }

    pub fn get_top_of_stack(&self) -> VirtAddr {
        self.init_stack.unwrap()
    }

    pub fn get_top_of_df_stack(&self) -> VirtAddr {
        self.ist.double_fault_stack.unwrap()
    }

    fn setup_tss(&mut self) {
        self.tss.ist_stacks[IST_DF] = self.ist.double_fault_stack.unwrap();
    }

    pub fn map_self_stage2(&mut self) -> Result<(), SvsmError> {
        let vaddr = VirtAddr::from(self as *const PerCpu);
        let paddr = virt_to_phys(vaddr);
        let flags = PTEntryFlags::data();

        self.get_pgtable().map_4k(SVSM_PERCPU_BASE, paddr, flags)
    }

    pub fn map_self(&mut self) -> Result<(), SvsmError> {
        let vaddr = VirtAddr::from(self as *const PerCpu);
        let paddr = virt_to_phys(vaddr);

        let self_mapping = Arc::new(VMPhysMem::new_mapping(paddr, PAGE_SIZE, true));
        self.vm_range.insert_at(SVSM_PERCPU_BASE, self_mapping)?;

        Ok(())
    }

    fn initialize_vm_ranges(&mut self) -> Result<(), SvsmError> {
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

    pub fn dump_vm_ranges(&self) {
        self.vm_range.dump_ranges();
    }

    pub fn setup(&mut self) -> Result<(), SvsmError> {
        // Allocate page-table
        self.allocate_page_table()?;

        // Map PerCpu data in own page-table
        self.map_self()?;

        // Reserve ranges for temporary mappings
        self.initialize_vm_ranges()?;

        // Setup GHCB
        self.setup_ghcb()?;

        // Allocate per-cpu init stack
        self.allocate_init_stack()?;

        // Allocate IST stacks
        self.allocate_ist_stacks()?;

        // Setup TSS
        self.setup_tss();

        // Initialize allocator for temporary mappings
        self.virt_range_init();

        Ok(())
    }

    // Setup code which needs to run on the target CPU
    pub fn setup_on_cpu(&self) -> Result<(), SvsmError> {
        self.register_ghcb()
    }

    pub fn load_pgtable(&mut self) {
        self.get_pgtable().load();
    }

    pub fn load_tss(&mut self) {
        gdt_mut().load_tss(&self.tss);
    }

    pub fn load(&mut self) {
        self.load_pgtable();
        self.load_tss();
    }

    pub fn shutdown(&mut self) -> Result<(), SvsmError> {
        if self.ghcb.is_null() {
            return Ok(());
        }

        unsafe { (*self.ghcb).shutdown() }
    }

    pub fn set_reset_ip(&mut self, reset_ip: u64) {
        self.reset_ip = reset_ip;
    }

    pub fn ghcb(&mut self) -> &'static mut GHCB {
        unsafe { self.ghcb.as_mut().unwrap() }
    }

    pub fn alloc_svsm_vmsa(&mut self) -> Result<(), SvsmError> {
        if self.svsm_vmsa.is_some() {
            // FIXME: add a more explicit error variant for this condition
            return Err(SvsmError::Mem);
        }

        let vaddr = allocate_new_vmsa(RMPFlags::GUEST_VMPL)?;
        let paddr = virt_to_phys(vaddr);

        self.svsm_vmsa = Some(VmsaRef::new(vaddr, paddr, false));

        Ok(())
    }

    pub fn get_svsm_vmsa(&mut self) -> &mut Option<VmsaRef> {
        &mut self.svsm_vmsa
    }

    pub fn prepare_svsm_vmsa(&mut self, start_rip: u64) {
        let mut vmsa = self.svsm_vmsa.unwrap();
        let vmsa_ref = vmsa.vmsa();

        vmsa_ref.tr = self.vmsa_tr_segment();
        vmsa_ref.rip = start_rip;
        vmsa_ref.rsp = self.get_top_of_stack().into();
        vmsa_ref.cr3 = self.get_pgtable().cr3_value().into();
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

    pub fn guest_vmsa_ref(&self) -> LockGuard<GuestVmsaRef> {
        self.shared.guest_vmsa.lock()
    }

    pub fn guest_vmsa(&mut self) -> &mut VMSA {
        let locked = self.shared.guest_vmsa.lock();

        assert!(locked.vmsa_phys().is_some());

        unsafe { SVSM_PERCPU_VMSA_BASE.as_mut_ptr::<VMSA>().as_mut().unwrap() }
    }

    pub fn alloc_guest_vmsa(&mut self) -> Result<(), SvsmError> {
        let vaddr = allocate_new_vmsa(RMPFlags::GUEST_VMPL)?;
        let paddr = virt_to_phys(vaddr);

        let vmsa = vmsa_mut_ref_from_vaddr(vaddr);
        init_guest_vmsa(vmsa, self.reset_ip);

        self.shared.update_guest_vmsa(paddr);

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

    pub fn caa_addr(&self) -> Option<VirtAddr> {
        let locked = self.shared.guest_vmsa.lock();
        let caa_phys = locked.caa_phys()?;
        let offset = caa_phys.page_offset();

        Some(SVSM_PERCPU_CAA_BASE + offset)
    }

    fn vmsa_tr_segment(&self) -> VMSASegment {
        VMSASegment {
            selector: SVSM_TSS,
            flags: SVSM_TR_FLAGS,
            limit: TSS_LIMIT as u32,
            base: (&self.tss as *const X86Tss) as u64,
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
    pub fn new_mapping(&mut self, mapping: Arc<Mapping>) -> Result<VMRMapping, SvsmError> {
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

    /// Allocate any candidate unallocated tasks from the global task list to our
    /// CPU runqueue.
    pub fn allocate_tasks(&mut self) {
        self.runqueue.lock_write().allocate();
    }

    /// Access the PerCpu runqueue protected with a lock
    pub fn runqueue(&self) -> &RWLock<RunQueue> {
        &self.runqueue
    }
}

pub fn this_cpu() -> &'static PerCpu {
    unsafe { SVSM_PERCPU_BASE.as_ptr::<PerCpu>().as_ref().unwrap() }
}

pub fn this_cpu_mut() -> &'static mut PerCpu {
    unsafe { SVSM_PERCPU_BASE.as_mut_ptr::<PerCpu>().as_mut().unwrap() }
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
