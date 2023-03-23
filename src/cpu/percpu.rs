// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use super::gdt::load_tss;
use super::tss::{X86Tss, IST_DF};
use crate::cpu::tss::TSS_LIMIT;
use crate::cpu::vmsa::init_guest_vmsa;
use crate::error::SvsmError;
use crate::locking::{LockGuard, RWLock, SpinLock};
use crate::mm::alloc::{allocate_page, allocate_zeroed_page};
use crate::mm::pagetable::{get_init_pgtable_locked, PageTable, PageTableRef};
use crate::mm::stack::{allocate_stack_addr, stack_base_pointer};
use crate::mm::{
    virt_to_phys, SVSM_PERCPU_BASE, SVSM_PERCPU_CAA_BASE, SVSM_PERCPU_VMSA_BASE,
    SVSM_STACKS_INIT_TASK, SVSM_STACK_IST_DF_BASE,
};
use crate::sev::ghcb::GHCB;
use crate::sev::utils::RMPFlags;
use crate::sev::vmsa::{allocate_new_vmsa, VMSASegment, VMSA};
use crate::types::{PhysAddr, VirtAddr};
use crate::types::{SVSM_TR_FLAGS, SVSM_TSS};
use crate::utils::{page_align, page_offset};
use alloc::vec::Vec;
use core::cell::SyncUnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

struct PerCpuInfo {
    apic_id: u32,
    addr: VirtAddr,
}

impl PerCpuInfo {
    const fn new(apic_id: u32, addr: VirtAddr) -> Self {
        PerCpuInfo {
            apic_id: apic_id,
            addr: addr,
        }
    }
}

// PERCPU areas virtual addresses into shared memory
pub static PERCPU_AREAS: PerCpuAreas = PerCpuAreas::new();

// We use a SyncUnsafeCell to allow for a static with interior
// mutability. It is like an UnsafeCell except it implements Sync,
// which allows the compiler to know that it is going to be accessed
// from multiple threads, but synchronization is left to the user. In
// our case we do not use any synchronization because writes to the
// structure only occur at initialization, from CPU 0, and reads
// should only occur after all writes are done.
pub struct PerCpuAreas {
    areas: SyncUnsafeCell<Vec<PerCpuInfo>>,
}

impl PerCpuAreas {
    const fn new() -> Self {
        Self {
            areas: SyncUnsafeCell::new(Vec::new()),
        }
    }

    unsafe fn push(&self, info: PerCpuInfo) {
        let ptr = self.areas.get().as_mut().unwrap();
        ptr.push(info);
    }

    // Fails if no such area exists or its address is NULL
    pub fn get(&self, apic_id: u32) -> Option<&'static PerCpu> {
        // For this to not produce UB the only invariant we must
        // uphold is that there are no mutations or mutable aliases
        // going on when casting via as_ref(). This only happens via
        // Self::push(), which is intentionally unsafe and private.
        let ptr = unsafe { self.areas.get().as_ref().unwrap() };
        ptr.iter().find(|info| info.apic_id == apic_id).map(|info| {
            let ptr = info.addr as *const PerCpu;
            unsafe { ptr.as_ref().unwrap() }
        })
    }
}

#[derive(Copy, Clone)]
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

    pub fn vmsa(&self) -> &mut VMSA {
        let ptr: *mut VMSA = self.vaddr as *mut VMSA;
        unsafe { ptr.as_mut().unwrap() }
    }
}

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

pub struct PerCpu {
    online: AtomicBool,
    apic_id: u32,
    pgtbl: SpinLock<PageTableRef>,
    ghcb: *mut GHCB,
    init_stack: Option<VirtAddr>,
    ist: IstStacks,
    tss: X86Tss,
    svsm_vmsa: Option<VmsaRef>,
    guest_vmsa: SpinLock<GuestVmsaRef>,
    reset_ip: u64,
}

impl PerCpu {
    pub const fn new() -> Self {
        PerCpu {
            online: AtomicBool::new(false),
            apic_id: 0,
            pgtbl: SpinLock::<PageTableRef>::new(PageTableRef::unset()),
            ghcb: ptr::null_mut(),
            init_stack: None,
            ist: IstStacks::new(),
            tss: X86Tss::new(),
            svsm_vmsa: None,
            guest_vmsa: SpinLock::new(GuestVmsaRef::new()),
            reset_ip: 0xffff_fff0u64,
        }
    }

    pub fn alloc(apic_id: u32) -> Result<*mut PerCpu, SvsmError> {
        let vaddr = allocate_zeroed_page()?;
        unsafe {
            let percpu = vaddr as *mut PerCpu;
            (*percpu) = PerCpu::new();
            (*percpu).apic_id = apic_id;
            PERCPU_AREAS.push(PerCpuInfo::new(apic_id, vaddr));
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
        let pgtable_ref = get_init_pgtable_locked().clone_shared()?;
        self.set_pgtable(pgtable_ref);
        Ok(())
    }

    pub fn set_pgtable(&mut self, pgtable: PageTableRef) {
        let mut my_pgtable = self.get_pgtable();
        *my_pgtable = pgtable;
    }

    fn allocate_init_stack(&mut self) -> Result<(), SvsmError> {
        allocate_stack_addr(SVSM_STACKS_INIT_TASK, &mut self.get_pgtable())
            .expect("Failed to allocate per-cpu init stack");
        self.init_stack = Some(SVSM_STACKS_INIT_TASK);
        Ok(())
    }

    fn allocate_ist_stacks(&mut self) -> Result<(), SvsmError> {
        allocate_stack_addr(SVSM_STACK_IST_DF_BASE, &mut self.get_pgtable())
            .expect("Failed to allocate percpu double-fault stack");

        self.ist.double_fault_stack = Some(SVSM_STACK_IST_DF_BASE);
        Ok(())
    }

    pub fn get_pgtable(&self) -> LockGuard<PageTableRef> {
        self.pgtbl.lock()
    }

    pub fn setup_ghcb(&mut self) -> Result<(), SvsmError> {
        let ghcb_page = allocate_page().expect("Failed to allocate GHCB page");
        self.ghcb = ghcb_page as *mut GHCB;
        unsafe { (*self.ghcb).init() }
    }

    pub fn register_ghcb(&self) -> Result<(), SvsmError> {
        unsafe { self.ghcb.as_ref().unwrap().register() }
    }

    pub fn get_top_of_stack(&self) -> VirtAddr {
        stack_base_pointer(self.init_stack.unwrap())
    }

    fn setup_tss(&mut self) {
        self.tss.ist_stacks[IST_DF] = stack_base_pointer(self.ist.double_fault_stack.unwrap());
    }

    pub fn map_self(&mut self) -> Result<(), SvsmError> {
        let vaddr = (self as *const PerCpu) as VirtAddr;
        let paddr = virt_to_phys(vaddr);
        let flags = PageTable::data_flags();

        self.get_pgtable().map_4k(SVSM_PERCPU_BASE, paddr, flags)
    }

    pub fn setup(&mut self) -> Result<(), SvsmError> {
        // Allocate page-table
        self.allocate_page_table()?;

        // Map PerCpu data in own page-table
        self.map_self()?;

        // Setup GHCB
        self.setup_ghcb()?;

        // Allocate per-cpu init stack
        self.allocate_init_stack()?;

        // Allocate IST stacks
        self.allocate_ist_stacks()?;

        // Setup TSS
        self.setup_tss();

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
        load_tss(&self.tss);
    }

    pub fn load(&mut self) {
        self.load_pgtable();
        self.load_tss();
    }

    pub fn shutdown(&mut self) -> Result<(), SvsmError> {
        if self.ghcb == ptr::null_mut() {
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
        if let Some(_) = self.svsm_vmsa {
            // FIXME: add a more explicit error variant for this condition
            return Err(SvsmError::Mem);
        }

        let vaddr = allocate_new_vmsa(RMPFlags::VMPL1)?;
        let paddr = virt_to_phys(vaddr);

        self.svsm_vmsa = Some(VmsaRef::new(vaddr, paddr, false));

        Ok(())
    }

    pub fn get_svsm_vmsa(&mut self) -> &mut Option<VmsaRef> {
        &mut self.svsm_vmsa
    }

    pub fn prepare_svsm_vmsa(&mut self, start_rip: u64) {
        let vmsa = self.svsm_vmsa.unwrap();

        vmsa.vmsa().tr = self.vmsa_tr_segment();
        vmsa.vmsa().rip = start_rip;
        vmsa.vmsa().rsp = self.get_top_of_stack().try_into().unwrap();
        vmsa.vmsa().cr3 = self.get_pgtable().cr3_value().try_into().unwrap();
    }

    pub fn unmap_guest_vmsa(&self) {
        assert!(self.apic_id == this_cpu().get_apic_id());
        self.get_pgtable().unmap_4k(SVSM_PERCPU_VMSA_BASE);
    }

    pub fn map_guest_vmsa(&self, paddr: PhysAddr) -> Result<(), SvsmError> {
        assert!(self.apic_id == this_cpu().get_apic_id());

        let flags = PageTable::data_flags();
        let vaddr = SVSM_PERCPU_VMSA_BASE;

        self.get_pgtable().map_4k(vaddr, paddr, flags)?;

        Ok(())
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

    pub fn guest_vmsa_ref(&self) -> LockGuard<GuestVmsaRef> {
        self.guest_vmsa.lock()
    }

    pub fn guest_vmsa(&self) -> &mut VMSA {
        let locked = self.guest_vmsa.lock();

        assert!(locked.vmsa_phys().is_some());

        unsafe { (SVSM_PERCPU_VMSA_BASE as *mut VMSA).as_mut().unwrap() }
    }

    pub fn alloc_guest_vmsa(&mut self) -> Result<(), SvsmError> {
        let vaddr = allocate_new_vmsa(RMPFlags::VMPL1)?;
        let paddr = virt_to_phys(vaddr);

        let vmsa = VMSA::from_virt_addr(vaddr);
        init_guest_vmsa(vmsa, self.reset_ip);

        self.update_guest_vmsa(paddr);

        Ok(())
    }

    pub fn unmap_caa(&self) {
        self.get_pgtable().unmap_4k(SVSM_PERCPU_CAA_BASE);
    }

    pub fn map_guest_caa(&self, paddr: PhysAddr) -> Result<(), SvsmError> {
        self.unmap_caa();

        let paddr_aligned = page_align(paddr);
        let flags = PageTable::data_flags();

        let vaddr = SVSM_PERCPU_CAA_BASE;

        self.get_pgtable().map_4k(vaddr, paddr_aligned, flags)?;

        Ok(())
    }

    pub fn caa_addr(&self) -> Option<VirtAddr> {
        let locked = self.guest_vmsa.lock();

        if locked.caa_phys().is_none() {
            return None;
        }

        let offset = page_offset(locked.caa_phys().unwrap());

        Some((SVSM_PERCPU_CAA_BASE + offset) as VirtAddr)
    }

    fn vmsa_tr_segment(&self) -> VMSASegment {
        VMSASegment {
            selector: SVSM_TSS,
            flags: SVSM_TR_FLAGS,
            limit: TSS_LIMIT as u32,
            base: (&self.tss as *const X86Tss) as u64,
        }
    }
}

unsafe impl Sync for PerCpu {}

pub fn this_cpu() -> &'static PerCpu {
    unsafe {
        let ptr = SVSM_PERCPU_BASE as *mut PerCpu;
        ptr.as_ref().unwrap()
    }
}

pub fn this_cpu_mut() -> &'static mut PerCpu {
    unsafe {
        let ptr = SVSM_PERCPU_BASE as *mut PerCpu;
        ptr.as_mut().unwrap()
    }
}

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

    pub fn register(&self, paddr: PhysAddr, apic_id: u32, guest_owned: bool) -> Result<(), ()> {
        let mut guard = self.vmsas.lock_write();
        if guard.iter().any(|vmsa| vmsa.paddr == paddr) {
            return Err(());
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
