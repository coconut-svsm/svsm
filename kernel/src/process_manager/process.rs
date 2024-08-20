extern crate alloc;

use core::cell::UnsafeCell;
use alloc::vec::Vec;
//use cpuarch::vmsa::GuestVMExit;
//use cpuarch::vmsa::VMSASegment;
use crate::address::PhysAddr;
use crate::cpu::percpu::this_cpu_mut;
use crate::cpu::percpu::this_cpu_shared;
use crate::cpu::percpu::this_cpu_unsafe;
use crate::cpu::percpu::PerCpuUnsafe;
//use crate::cpu::vmsa::vmsa_mut_ref_from_vaddr;
//use crate::cpu::vmsa::vmsa_ref_from_vaddr;
use crate::mm::alloc::free_page;
use crate::mm::SVSM_PERCPU_VMSA_BASE;
//use crate::attestation::process;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
//use crate::sp_pagetable::tmp_mapping::TemporaryPageMapping;
//Testing
use crate::sp_pagetable::*;
use crate::sev::RMPFlags;
use crate::sev::rmp_adjust;
//use crate::cpu::percpu::this_cpu_mut;
use crate::cpu::percpu::PERCPU_VMSAS;
use crate::cpu::percpu::this_cpu;
use core::mem::replace;
use crate::mm::PAGE_SIZE;
use crate::utils::zero_mem_region;
use cpuarch::vmsa::VMSA;
use crate::sev::utils::rmp_revoke_guest_access;
use crate::cpu::flush_tlb_global_sync;
use crate::mm::virt_to_phys;
use crate::mm::alloc::allocate_zeroed_page;
use crate::types::PageSize;
use crate::address::VirtAddr;
use crate::mm::PerCPUPageMappingGuard;
use crate::sev::utils::rmp_set_guest_vmsa;
use core::ptr::null_mut;

//use crate::time::*;

//use crate::protocols::core::core_create_vcpu_error_restore; //

trait FromVAddr {
    fn from_virt_addr(v: VirtAddr) -> &'static mut VMSA;
}

impl FromVAddr for VMSA {
    fn from_virt_addr(v: VirtAddr) -> &'static mut VMSA{
        unsafe { v.as_mut_ptr::<VMSA>().as_mut().unwrap() }
    }
}

#[derive(Clone,Copy,Debug,PartialEq)]
pub enum TrustedProcessType {
    Undefined,
    Zygote,
    Trustlet,
}
pub const UNDEFINED_PROCESS: u32 = 0;
pub const ZYGOTE_PROCESS: u32 = 1;
pub const TRUSTLET_PROCESS: u32 = 2;

pub static PROCESS_STORE: TrustedProcessStore = TrustedProcessStore::new();

#[derive(Debug)]
pub struct TrustedProcessStore{
    processes: UnsafeCell<Vec<TrustedProcess>>,
}

unsafe impl Sync for TrustedProcessStore {}

impl TrustedProcessStore {
    const fn new() -> Self {
        Self {
            processes: UnsafeCell::new(Vec::new()),
        }
    }
    pub fn push(&self, process: TrustedProcess){
        let ptr: &mut Vec<TrustedProcess> = unsafe { self.processes.get().as_mut().unwrap() };
        ptr.push(process);
    }
    pub fn init(&self, size: u32){
        let empty_process = TrustedProcess::empty();
        for _ in 0..size  {
            self.push(empty_process);
        }
    }
    pub fn insert(&self, p: TrustedProcess) -> i64 {
        let ptr: &mut Vec<TrustedProcess> = unsafe { self.processes.get().as_mut().unwrap() };
        for i in 0..(ptr.len()) {
            if ptr[i].process_type == TrustedProcessType::Undefined {
                ptr[i] = p;
                return i.try_into().unwrap();
            }
        }
        -1
    }

    pub fn get(&self, pid: ProcessID) -> &mut TrustedProcess {
        let ptr = unsafe { self.processes.get().as_mut().unwrap() };
        &mut ptr[pid.0]
    }

}

#[derive(Clone,Copy,Debug)]
pub struct ProcessData(PhysAddr);

impl ProcessData {
    pub fn dublicate_read_only(&self) -> ProcessData{
        ProcessData(self.0)
    }
    pub fn append_data(&self){
        
    }
}

#[derive(Clone,Copy,Debug)]
pub struct ProcessID(usize);

#[derive(Clone,Copy,Debug)]
pub struct TrustedProcess {
    process_type: TrustedProcessType,
    data: ProcessData,
    page_table: *mut PageTableReference,
    vmsa: VirtAddr,
    len: u64,
    input: VirtAddr,
    output: VirtAddr,
    pub hash: [u8; 32],
}

impl TrustedProcess {

    const fn new(process_type: TrustedProcessType, data: PhysAddr, len: u64, hash: [u8; 32])->Self{
        Self {process_type, data: ProcessData(data), page_table: null_mut(), vmsa: VirtAddr::null(), len, input: VirtAddr::null(), output: VirtAddr::null(),  hash}
    }

    fn create_zygote_page_table(data: ProcessData) -> *mut PageTableReference {

        let vaddr_page_table_ref = allocate_zeroed_page().unwrap();
        let vaddr_page_table_top = allocate_zeroed_page().unwrap();
        let paddr_page_table_top = virt_to_phys(vaddr_page_table_top);
        rmp_adjust(vaddr_page_table_top, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        let mut sub_pages: [VirtAddr;5]  = [VirtAddr::from(0u64),VirtAddr::from(0u64),VirtAddr::from(0u64),VirtAddr::from(0u64),VirtAddr::from(0u64)];
        let mut sub_pages_phy: [PhysAddr; 5] = [PhysAddr::from(0u64),PhysAddr::from(0u64),PhysAddr::from(0u64),PhysAddr::from(0u64),PhysAddr::from(0u64)];
        for i in 0..5 {
            sub_pages[i] = allocate_zeroed_page().unwrap();
            sub_pages_phy[i] = virt_to_phys(sub_pages[i]);
            rmp_adjust(sub_pages[i], RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        }        
        let page_table_ref: &mut PageTableReference = unsafe { vaddr_page_table_ref.as_mut_ptr::<PageTableReference>().as_mut().unwrap() };
        page_table_ref.init(paddr_page_table_top, vaddr_page_table_top, &sub_pages_phy, &sub_pages);
        page_table_ref.mount();

        log::info!("Using the following address {:#}",data.0);
        //panic!("Stop");
        let _ = page_table_ref.map_4k_page(VirtAddr::from(0x8000000000u64), data.0, PageFlags::exec()| PageFlags::USER_ACCESSIBLE);
        let mapping_guard = PerCPUPageMappingGuard::create_4k(data.0).unwrap();
        let vaddr_data = mapping_guard.virt_addr();
        rmp_adjust(vaddr_data, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        log::info!("ZYGOTE PAGE TABLE:");
        page_table_ref.dump();

        vaddr_page_table_ref.as_mut_ptr::<PageTableReference>()
    }

    fn duplicate_page_table_ro(page_table_ref_ptr: *mut PageTableReference, input: VirtAddr, output: VirtAddr) -> *mut PageTableReference {
        let page_table_ref_base: &mut PageTableReference = unsafe {page_table_ref_ptr.as_mut().unwrap()};
        let page_table_ref = page_table_ref_base;





        /* 
        let vaddr_page_table_ref = allocate_zeroed_page().unwrap();


        let vaddr_page_table_top = allocate_zeroed_page().unwrap();
        let paddr_page_table_top = virt_to_phys(vaddr_page_table_top);
        rmp_adjust(vaddr_page_table_top, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        let mut sub_pages: [VirtAddr;5]  = [VirtAddr::from(0u64),VirtAddr::from(0u64),VirtAddr::from(0u64),VirtAddr::from(0u64),VirtAddr::from(0u64)];
        let mut sub_pages_phy: [PhysAddr; 5] = [PhysAddr::from(0u64),PhysAddr::from(0u64),PhysAddr::from(0u64),PhysAddr::from(0u64),PhysAddr::from(0u64)];
        for i in 0..5 {
            sub_pages[i] = allocate_zeroed_page().unwrap();
            sub_pages_phy[i] = virt_to_phys(sub_pages[i]);
            rmp_adjust(sub_pages[i], RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        }

        let page_table_ref: &mut PageTableReference = unsafe { vaddr_page_table_ref.as_mut_ptr::<PageTableReference>().as_mut().unwrap() };



        page_table_ref.init(paddr_page_table_top, vaddr_page_table_top, &sub_pages_phy, &sub_pages);
        page_table_ref.mount();
        //log::info!("TRUSTLET PAGE TABLE0:");
        //page_table_ref.dump();
        let data = page_table_ref_base.page_walk_pub(VirtAddr::from(0x8000000000u64));
        page_table_ref.map_4k_page(VirtAddr::from(0x8000000000u64), data, PageFlags::exec()| PageFlags::USER_ACCESSIBLE);
    
        log::info!("TRUSTLET PAGE TABLE1:");
        page_table_ref.dump();
        */


        for e in 0..5  {
            let vaddr_mem = allocate_zeroed_page().unwrap();
            let paddr_mem = virt_to_phys(vaddr_mem);
            rmp_adjust(vaddr_mem, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
            let _ = page_table_ref.map_4k_page(VirtAddr::from(0x8000000000u64)+PAGE_SIZE*(3+e), paddr_mem, PageFlags::data()| PageFlags::USER_ACCESSIBLE);

        }


        let vaddr_stack = output;
        let paddr_stack = virt_to_phys(vaddr_stack);

        let vaddr_res = input;
        let paddr_res = virt_to_phys(vaddr_res);
        rmp_adjust(vaddr_res, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        let _ = page_table_ref.map_4k_page(VirtAddr::from(0x8000000000u64)+PAGE_SIZE*2, paddr_res, PageFlags::data()| PageFlags::USER_ACCESSIBLE);


        rmp_adjust(vaddr_stack, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        let _ = page_table_ref.map_4k_page(VirtAddr::from(0x8000000000u64)+PAGE_SIZE, paddr_stack, PageFlags::data()| PageFlags::USER_ACCESSIBLE);
        //let _ = page_table_ref.map_4k_page(target, addr, flags);


        page_table_ref_ptr
        //vaddr_page_table_ref.as_mut_ptr::<PageTableReference>()

    }

    pub fn zygote(d: PhysAddr, len: u64) -> Self{
        let hash = [0u8;32];
        let vmsa: VirtAddr = unsafe {this_cpu_unsafe().as_mut().unwrap().get_trustlet_vmsa()};
        
        //let vaddr_vmsa_new: VirtAddr = allocate_zeroed_page().unwrap();
        //let vmsa_new = vmsa_mut_ref_from_vaddr(vaddr_vmsa_new);
        
        

        let vmsa_: &mut VMSA = unsafe {vmsa.as_mut_ptr::<VMSA>().as_mut().unwrap()};
        vmsa_.rip = 0x8000000000u64;

        let mut process = Self::new(TrustedProcessType::Zygote, d, len, hash);
        process.vmsa = vmsa;
        process.page_table = TrustedProcess::create_zygote_page_table(process.data);
        super::super::attestation::process::hash_process(&mut process);
        process
    }

    fn dublicate(pid: ProcessID) -> TrustedProcess {
        let process = PROCESS_STORE.get(pid);

        let vmsa: VirtAddr = unsafe{this_cpu_unsafe().as_mut().unwrap().get_trustlet_vmsa()};
        let vmsa_: &mut VMSA = unsafe {vmsa.as_mut_ptr::<VMSA>().as_mut().unwrap()};
        vmsa_.rip = 0x8000000000u64;
        
        let input: VirtAddr = allocate_zeroed_page().unwrap();
        let output: VirtAddr = allocate_zeroed_page().unwrap();

        TrustedProcess { process_type: TrustedProcessType::Trustlet, data: process.data.dublicate_read_only(), page_table: TrustedProcess::duplicate_page_table_ro(process.page_table,input,output),vmsa, len: process.len,input, output, hash: process.hash }
    }

    pub fn trustlet(parent: ProcessID, _d: PhysAddr, _len: u64) -> Self{
        let _hash = [0u8;32];
        let mut trustlet = TrustedProcess::dublicate(parent);
        super::super::attestation::process::hash_process(&mut trustlet);
        trustlet
    }

    pub fn empty() -> Self {
        Self::new(TrustedProcessType::Undefined, PhysAddr::from(0u64), 0, [0u8;32])
    }

    pub fn delete(&self) -> bool {
        true
    }

}

pub fn check_vmsa_ind(new: &VMSA, sev_features: u64, svme_mask: u64, vmpl_level: u64) -> bool {
    new.vmpl == vmpl_level as u8
        && new.efer & svme_mask == svme_mask
        && new.sev_features == sev_features
}


pub fn create_tmp_page_tabel() -> (*mut PageTableReference, PhysAddr) {
    
    let ref_page = allocate_zeroed_page().unwrap();
    let _ref_page_phy = virt_to_phys(ref_page);

    rmp_adjust(ref_page, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();

    let table_page = allocate_zeroed_page().unwrap();
    let table_page_phy = virt_to_phys(table_page);
    rmp_adjust(table_page, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
    let mut sub_pages: [VirtAddr;5]  = [VirtAddr::from(0u64),VirtAddr::from(0u64),VirtAddr::from(0u64),VirtAddr::from(0u64),VirtAddr::from(0u64)];
    let mut sub_pages_phy: [PhysAddr; 5] = [PhysAddr::from(0u64),PhysAddr::from(0u64),PhysAddr::from(0u64),PhysAddr::from(0u64),PhysAddr::from(0u64)];
    for i in 0..5 {
        sub_pages[i] = allocate_zeroed_page().unwrap();
        sub_pages_phy[i] = virt_to_phys(sub_pages[i]);
        rmp_adjust(sub_pages[i], RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
    }
    let r = unsafe { ref_page.as_mut_ptr::<PageTableReference>().as_mut().unwrap() };
    r.init(table_page_phy, table_page, &sub_pages_phy, &sub_pages);
    r.mount();
    (ref_page.as_mut_ptr::<PageTableReference>(), table_page_phy)
}

pub fn vmpl1_init() -> Result<(), SvsmReqError>{

    let cpu_unsafe: &mut PerCpuUnsafe = unsafe { this_cpu_unsafe().as_mut().unwrap() };

    if cpu_unsafe.is_trustlet_vmsa() {
        let cpu = this_cpu_mut().get_apic_id();
        log::info!("Trustlet vCore #{} already initialized", cpu);
        return Ok(());
    }


    let tmp_vmsa_store = allocate_zeroed_page().unwrap();
    let vmsa_copy = unsafe { tmp_vmsa_store.as_mut_ptr::<VMSA>().as_mut().unwrap()};
    *vmsa_copy = unsafe { *SVSM_PERCPU_VMSA_BASE.as_mut_ptr::<VMSA>().as_mut().unwrap() };

    let vaddr_vmsa = allocate_zeroed_page().unwrap();
    let paddr_vmsa =virt_to_phys(vaddr_vmsa);

    let vaddr_stack = allocate_zeroed_page().unwrap();
    let paddr_stack = virt_to_phys(vaddr_stack);
    let tmp = allocate_zeroed_page().unwrap();
    let t2 = unsafe { tmp.as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};
    let t: [u8; 6] = [0x0f, 0xa2, 0xeb, 0x00, 0xeb, 0xfe]; //cpuid; jmp +0;jmp -2;
    for i in 0..6 {
        t2[i] = t[i];
    }
    let paddr_pages = virt_to_phys(tmp);
    //

    log::info!("Allocating new page table");
    let page_table = create_tmp_page_tabel();
    let page_table_phy = page_table.1;
    let page_table: &mut PageTableReference = unsafe { page_table.0.as_mut().unwrap() };


    page_table.map_4k_page(VirtAddr::from(0x8000000000u64), paddr_pages, PageFlags::exec() | PageFlags::USER_ACCESSIBLE ).unwrap();
    page_table.map_4k_page(VirtAddr::from(0x8000000000u64)+PAGE_SIZE, paddr_stack, PageFlags::data() | PageFlags::USER_ACCESSIBLE).unwrap();
    
    
    //page_table.dump();

    let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr_pages)?;
    let vaddr_pages = mapping_guard.virt_addr();
    //let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr_stack)?;
    //let vaddr_stack = mapping_guard.virt_addr();
    //let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr_vmsa)?;
    //let vaddr_vmsa = mapping_guard.virt_addr();
    
    
    flush_tlb_global_sync();
  
    rmp_adjust(vaddr_pages, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular)?;
    rmp_adjust(vaddr_stack, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular)?;
    rmp_adjust(vaddr_vmsa, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular)?;
    rmp_adjust(vaddr_pages, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular)?;

    flush_tlb_global_sync();

    rmp_set_guest_vmsa(vaddr_vmsa)?;
    rmp_revoke_guest_access(vaddr_vmsa, PageSize::Regular)?;
    rmp_adjust(
        vaddr_vmsa,
        RMPFlags::VMPL1 | RMPFlags::VMSA,
        PageSize::Regular,
    )?;
    let vmsa = VMSA::from_virt_addr(vaddr_vmsa);
    zero_mem_region(vaddr_vmsa, vaddr_vmsa + PAGE_SIZE);
    let locked = this_cpu_shared().guest_vmsa.lock();
    let vmsa_ptr = unsafe { SVSM_PERCPU_VMSA_BASE.as_mut_ptr::<VMSA>().as_mut().unwrap() };
    _ = replace(vmsa,*vmsa_ptr); 
    drop(locked);

    vmsa.vmpl = 1;
    vmsa.cpl = 3;
    vmsa.cr3 = u64::from(page_table_phy);
    vmsa.rbp = u64::from(0x8000000000u64)+2*4096-1;
    vmsa.rsp = u64::from(0x8000000000u64)+2*4096-1;
    vmsa.efer = vmsa.efer | 1u64 << 12;
    vmsa.rip = u64::from(0x8000000000u64);
    vmsa.sev_features = vmsa_ptr.sev_features | 4; // VC Reflect feature
     
    let svme_mask: u64 = 1u64 << 12;
    if !check_vmsa_ind(vmsa, vmsa.sev_features | 4, svme_mask,RMPFlags::VMPL1.bits()) {
        log::info!("VMSA Check failed");
        log::info!("Bits: {}",vmsa.vmpl == RMPFlags::VMPL3.bits() as u8);
        log::info!("Efer & vsme_mask: {}", vmsa.efer & svme_mask == svme_mask);
        log::info!("SEV features: {}", vmsa.sev_features == vmsa.sev_features);
        if vmsa.efer & svme_mask == svme_mask {
            PERCPU_VMSAS.unregister(paddr_vmsa, false).unwrap();
            //core_create_vcpu_error_restore(vaddr_vmsa)?;
            return Err(SvsmReqError::invalid_parameter());   
        }
    }

    log::info!("{:?}",vmsa);

    let apic_id = this_cpu().get_apic_id();
    PERCPU_VMSAS.register(paddr_vmsa, apic_id, true)?;

    assert!(PERCPU_VMSAS.set_used(paddr_vmsa) == Some(apic_id));
    unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(paddr_vmsa,u64::from(apic_id), 1, vmsa.sev_features | 4)?}
    vmsa.rip = u64::from(0x8000000000u64);
    log::info!("Second try");
    unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(paddr_vmsa,u64::from(apic_id), 1, vmsa.sev_features | 4)?}
    vmsa.rip = u64::from(0x8000000000u64);
    log::info!("Third try");
    unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(paddr_vmsa,u64::from(apic_id), 1, vmsa.sev_features | 4)?}
    log::info!("Initilized VMPL1 Trustlet for #{}",apic_id);


    page_table.dump();
    //log::info!("Guest Exit Code: {}!!!!!!!!!!!!!!!!!!!!!!!",vmsa.guest_exit_code as u64);
    //log::info!("VMSA: {:?}", vmsa);
    log::info!("");
    //
    page_table.unmount();
    log::info!("unmount done");
    for i in page_table.pages_virt {
        if i == VirtAddr::from(0u64) {
            break;
        }
        log::info!("before rmp_adjust {}", i);
        rmp_adjust(i, RMPFlags::VMPL1 | RMPFlags::NONE, PageSize::Regular)?;
        log::info!("rmp_adjust {}", i);
        log::info!("before Free {}",i);
        free_page(i);
        log::info!("Free {}",i);
    }
    log::info!("page-table extra pages");
    rmp_adjust(page_table.table_virt, RMPFlags::VMPL1 | RMPFlags::NONE, PageSize::Regular)?;
    free_page(page_table.table_virt);
    log::info!("page-table table");
    rmp_adjust(vaddr_pages, RMPFlags::VMPL1 | RMPFlags::NONE, PageSize::Regular)?;
    rmp_adjust(vaddr_stack, RMPFlags::VMPL1 | RMPFlags::NONE, PageSize::Regular)?;
    log::info!("Changed permissions");
    free_page(tmp);
    log::info!("Free tmp");
    free_page(vaddr_stack);
    log::info!("Free stack");

    cpu_unsafe.set_trustlet_vmsa(vaddr_vmsa);
    
    

    return Ok(());

}

pub fn create_trusted_process(params: &mut RequestParams, _t: TrustedProcessType) -> Result<(), SvsmReqError>{
    /* End of Test code */
    /* Start of actual Trustlet creation */
    match _t {
        TrustedProcessType::Undefined => panic!("Invalid Creation Request"),
        TrustedProcessType::Zygote => {

            log::info!("create_trusted_process(): Creating and registering Zygote");
            let len = params.rcx;
            let zygote_address = PhysAddr::from(params.r8);
            let z: TrustedProcess = TrustedProcess::zygote(zygote_address, len);
            let res = PROCESS_STORE.insert(z);
            // if res < 0 {
            //     params.rcx = u64::from_ne_bytes(res.to_ne_bytes());
            // }
            params.rcx = u64::from_ne_bytes(res.to_ne_bytes());
            log::info!("Created Zygote #{}", params.rcx);
            Ok(())
        },
        TrustedProcessType::Trustlet => {

            log::info!("create_trusted_process(): Creating and registering Trustlet");
            let len = params.rcx;
            //let _trustlet_address = PhysAddr::from(params.r8);
            let trustlet = TrustedProcess::trustlet(ProcessID(params.rdx as usize), PhysAddr::null(), len);
            if trustlet.process_type == TrustedProcessType::Undefined {
                params.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
                return Ok(());
            } 

            let res = PROCESS_STORE.insert(trustlet);
            params.rcx = u64::from_ne_bytes(res.to_ne_bytes());
            Ok(())

        },
    }
}

pub fn dublicate_trusted_process(_params: &mut RequestParams) -> Result<(), SvsmReqError> {
    todo!()
}

pub fn append_trusted_process(_params: &mut RequestParams) -> Result<(), SvsmReqError> {
    todo!()
}

pub fn delete_trusted_process(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let process_id = ProcessID(params.rcx as usize);
    let process = PROCESS_STORE.get(process_id);
    process.delete();
    Ok(())
}

pub fn attest_trusted_process(_params: &mut RequestParams) -> Result<(), SvsmReqError> {
    todo!()
}




pub fn invoke_trustlet(params: &mut RequestParams) -> Result<(), SvsmReqError> {

    log::info!("Starting Trustlet invocation");

    let trustlet_id = params.rcx;
    let trustlet = PROCESS_STORE.get(ProcessID(trustlet_id.try_into().unwrap()));

    log::info!("{:?}", trustlet);
    log::info!("Test1");

    let vaddr_vmsa = trustlet.vmsa;
    let paddr_vmsa = virt_to_phys(vaddr_vmsa);
    log::info!("Test2");
    let vmsa = VMSA::from_virt_addr(vaddr_vmsa);
    //vmsa.rbp = u64::from(0x8000000000u64)+1*4096-1;
    //vmsa.rsp = u64::from(0x8000000000u64)+1*4096-1;
    vmsa.cr3 = u64::from(unsafe {(*trustlet.page_table).table_phy});
    vmsa.rip = 0x8000000000u64;
    vmsa.efer = vmsa.efer | 1u64 << 12;
    //log::info!("{:?}",vmsa);
    
    
    log::info!("Test3");
    let apic_id = this_cpu().get_apic_id();
    //PERCPU_VMSAS.register(paddr_vmsa, apic_id, true)?;


    let svme_mask: u64 = 1u64 << 12;
    if !check_vmsa_ind(vmsa, vmsa.sev_features | 4, svme_mask,RMPFlags::VMPL1.bits()) {
        log::info!("VMSA Check failed");
        log::info!("Bits: {}",vmsa.vmpl == RMPFlags::VMPL3.bits() as u8);
        log::info!("Efer & vsme_mask: {}", vmsa.efer & svme_mask == svme_mask);
        log::info!("SEV features: {}", vmsa.sev_features == vmsa.sev_features);
        if vmsa.efer & svme_mask == svme_mask {
            PERCPU_VMSAS.unregister(paddr_vmsa, false).unwrap();
            //core_create_vcpu_error_restore(vaddr_vmsa)?;
            return Err(SvsmReqError::invalid_parameter());   
        }
    }
    

    /*let ptr = unsafe {&*trustlet.page_table};
    let data_page = ptr.page_walk_pub(VirtAddr::from(0x8000000000u64));
    log::info!("Page Addr: {}", data_page);
    let mapping = TemporaryPageMapping::create_4k(data_page).unwrap();
    let data_page_mapped = mapping.virt_addr().as_mut_ptr::<[u8;4096]>();
    log::info!("{:?}",data_page_mapped);*/
    //unsafe {(*trustlet.page_table).dump()};

    //log::info!("VMSA: {:?}",vmsa);
    //return Ok(());
    //assert!(PERCPU_VMSAS.set_used(paddr_vmsa) == Some(apic_id));
    log::info!("Test starting invocation");
    //

    let vmexit = vmsa.guest_exit_code as u64;
    log::info!("Exit code: {}",vmexit);
    //let t1 = get_current_time();

    unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(paddr_vmsa,u64::from(apic_id), 1, vmsa.sev_features | 4)?}
    let vmexit = vmsa.guest_exit_code as u64;
    log::info!("Exit code: {}",vmexit);
    let rip = vmsa.rip;
    vmsa.rip += 0x2;
    unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(paddr_vmsa,u64::from(apic_id), 1, vmsa.sev_features | 4)?}
    //0x72 (114) in guest_exit_code stand for vmexit_cpuid
    //unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(paddr_vmsa,u64::from(apic_id), 1, vmsa.sev_features | 4)?}
    //unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(paddr_vmsa,u64::from(apic_id), 1, vmsa.sev_features | 4)?}
    let rip = vmsa.rip;
    //log::info!("IP3: {}", rip);
    //let t2 = get_current_time();
    /* 
    log::info!("Test after invocation");
    log::info!("Cyles ({}-{}): {}",t2,t1,t2-t1);
    log::info!("Milliseconds: {}",(t2-t1).to_millisconds());
    log::info!("Microseconds: {}",(t2-t1).to_microseconds());
    log::info!("Nanoseconds: {}",(t2-t1).to_nanoseconds());
    let arr = unsafe { trustlet.input.as_mut_ptr::<[u64;512]>().as_mut().unwrap()};

    //log::info!("Read Time: {}\nWrite Time: {}", arr[511],arr[510]);
    log::info!("Read Time: {}\nWrite Time: {}", arr[0],arr[1]);
*/
    params.rcx = 0;
    Ok(())
}