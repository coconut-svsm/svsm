extern crate alloc;

use core::cell::UnsafeCell;
use alloc::vec::Vec;
use cpuarch::vmsa::VMSASegment;
use crate::address::PhysAddr;
use crate::cpu::percpu::this_cpu_shared;
use crate::cpu::percpu::this_cpu_unsafe;
use crate::mm::SVSM_PERCPU_VMSA_BASE;
//use crate::attestation::process;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;

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
    len: u64,
    pub hash: [u8; 32],
}
impl TrustedProcess {

    const fn new(process_type: TrustedProcessType, data: PhysAddr, len: u64, hash: [u8; 32])->Self{
        Self {process_type, data: ProcessData(data), len, hash}
    }

    pub fn zygote(d: PhysAddr, len: u64) -> Self{
        let hash = [0u8;32];
        let mut process = Self::new(TrustedProcessType::Zygote, d, len, hash);
        super::super::attestation::process::hash_process(&mut process);
        process
    }

    fn dublicate(pid: ProcessID) -> TrustedProcess {
        let process = PROCESS_STORE.get(pid);
        TrustedProcess { process_type: TrustedProcessType::Trustlet, data: process.data.dublicate_read_only(), len: process.len, hash: process.hash }
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
    set_ecryption_mask_address_size();
    log::info!("Creating tmp page table");
    let ref_page = allocate_zeroed_page().unwrap();
    let _ref_page_phy = virt_to_phys(ref_page);
    log::info!("Allocating ref page");
    rmp_adjust(ref_page, RMPFlags::VMPL2 | RMPFlags::VMPL3 | RMPFlags::VMPL1 | RMPFlags::VMPL0 | RMPFlags::RWX, PageSize::Regular).unwrap();
    log::info!("Allocating table pages");
    let table_page = allocate_zeroed_page().unwrap();
    let table_page_phy = virt_to_phys(table_page);
    rmp_adjust(table_page, RMPFlags::VMPL2 | RMPFlags::VMPL3 | RMPFlags::VMPL1 | RMPFlags::VMPL0 | RMPFlags::RWX, PageSize::Regular).unwrap();
    let mut sub_pages: [VirtAddr;5]  = [VirtAddr::from(0u64),VirtAddr::from(0u64),VirtAddr::from(0u64),VirtAddr::from(0u64),VirtAddr::from(0u64)];
    let mut sub_pages_phy: [PhysAddr; 5] = [PhysAddr::from(0u64),PhysAddr::from(0u64),PhysAddr::from(0u64),PhysAddr::from(0u64),PhysAddr::from(0u64)];
    for i in 0..5 {
        sub_pages[i] = allocate_zeroed_page().unwrap();
        sub_pages_phy[i] = virt_to_phys(sub_pages[i]);
        rmp_adjust(sub_pages[i], RMPFlags::VMPL2 | RMPFlags::VMPL3 | RMPFlags::VMPL1 | RMPFlags::VMPL0 | RMPFlags::RWX, PageSize::Regular).unwrap();
    }
    let r = unsafe { ref_page.as_mut_ptr::<PageTableReference>().as_mut().unwrap() };
    r.init(table_page_phy, &sub_pages_phy);
    r.mount();
    log::info!("Done with tmp page table creation process");
    (ref_page.as_mut_ptr::<PageTableReference>(), table_page_phy)
}

pub fn create_trusted_process(params: &mut RequestParams, _t: TrustedProcessType) -> Result<(), SvsmReqError>{

    /* Test code for the execution withint a different VMPL level (only uses Monitor Memory)*/

    log::info!("VMSA host: \n{:?}", unsafe { SVSM_PERCPU_VMSA_BASE.as_mut_ptr::<VMSA>().as_mut().unwrap() } );

    let tmp_vmsa_store = allocate_zeroed_page().unwrap();
    let vmsa_copy = unsafe { tmp_vmsa_store.as_mut_ptr::<VMSA>().as_mut().unwrap()};
    *vmsa_copy = unsafe { *SVSM_PERCPU_VMSA_BASE.as_mut_ptr::<VMSA>().as_mut().unwrap() };

    let paddr_vmsa =virt_to_phys(allocate_zeroed_page().unwrap());
    let paddr_stack = virt_to_phys(allocate_zeroed_page().unwrap());
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
    let page_table = unsafe { page_table.0.as_mut().unwrap() };

    page_table.map_4k_page(VirtAddr::from(0x8000000000u64), paddr_pages, PageFlags::exec()).unwrap();
    page_table.map_4k_page(VirtAddr::from(0x8000000000u64)+PAGE_SIZE, paddr_stack, PageFlags::data()).unwrap();
    
    page_table.dump();

    let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr_pages)?;
    let vaddr_pages = mapping_guard.virt_addr();
    let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr_stack)?;
    let vaddr_stack = mapping_guard.virt_addr();
    let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr_vmsa)?;
    let vaddr_vmsa = mapping_guard.virt_addr();
    
    
    flush_tlb_global_sync();
    let vmsa = VMSA::from_virt_addr(vaddr_vmsa);
    zero_mem_region(vaddr_vmsa, vaddr_vmsa + PAGE_SIZE);

    
    let locked = this_cpu_shared().guest_vmsa.lock();
    let vmsa_ptr = unsafe { SVSM_PERCPU_VMSA_BASE.as_mut_ptr::<VMSA>().as_mut().unwrap() };
    _ = replace(vmsa,*vmsa_ptr); 
    drop(locked);
    //log::info!("Changing VMPL level of memory");
    
    //------ Breaks the kernel (prevents from booting); Does not break anymore in release mode 
    rmp_adjust(vaddr_pages, RMPFlags::VMPL3 | RMPFlags::RWX, PageSize::Regular)?;
    rmp_adjust(vaddr_stack, RMPFlags::VMPL3 | RMPFlags::RWX, PageSize::Regular)?;
    rmp_adjust(vaddr_vmsa, RMPFlags::VMPL3 | RMPFlags::RWX, PageSize::Regular)?;
    rmp_adjust(vaddr_pages, RMPFlags::VMPL2 | RMPFlags::RWX, PageSize::Regular)?;
    rmp_adjust(vaddr_vmsa, RMPFlags::VMPL2 | RMPFlags::VMPL3 | RMPFlags::VMPL1 | RMPFlags::VMPL0 | RMPFlags::VMSA, PageSize::Regular)?;
    


    flush_tlb_global_sync();

    rmp_set_guest_vmsa(vaddr_vmsa)?;
    rmp_revoke_guest_access(vaddr_vmsa, PageSize::Regular)?;
    rmp_adjust(
        vaddr_vmsa,
        RMPFlags::VMPL3 | RMPFlags::VMSA,
        PageSize::Regular,
    )?;
    let vmsa = VMSA::from_virt_addr(vaddr_vmsa);
    zero_mem_region(vaddr_vmsa, vaddr_vmsa + PAGE_SIZE);
    let locked = this_cpu_shared().guest_vmsa.lock();
    let vmsa_ptr = unsafe { SVSM_PERCPU_VMSA_BASE.as_mut_ptr::<VMSA>().as_mut().unwrap() };
    _ = replace(vmsa,*vmsa_ptr); 
    drop(locked);

    vmsa.vmpl = 3;
    vmsa.cr3 = u64::from(page_table_phy);
    vmsa.rbp = u64::from(0x8000000000u64)+2*4096-1;
    vmsa.rsp = u64::from(0x8000000000u64)+2*4096-1;
    vmsa.efer = vmsa.efer | 1u64 << 12;
    vmsa.rip = u64::from(0x8000000000u64);
    vmsa.sev_features = vmsa_ptr.sev_features | 4; // VC Reflection feature
     

    log::info!("Trustlet VMSA: {:?}", vmsa);

    let svme_mask: u64 = 1u64 << 12;
    if !check_vmsa_ind(vmsa, params.sev_features | 4, svme_mask,RMPFlags::VMPL3.bits()) {
        log::info!("VMSA Check failed");
        log::info!("Bits: {}",vmsa.vmpl == RMPFlags::VMPL3.bits() as u8);
        log::info!("Efer & vsme_mask: {}", vmsa.efer & svme_mask == svme_mask);
        log::info!("SEV features: {}", vmsa.sev_features == params.sev_features);
        if vmsa.efer & svme_mask == svme_mask {
            PERCPU_VMSAS.unregister(paddr_vmsa, false).unwrap();
            //core_create_vcpu_error_restore(vaddr_vmsa)?;
            return Err(SvsmReqError::invalid_parameter());   
        }
    }


    let apic_id = this_cpu().get_apic_id();
    PERCPU_VMSAS.register(paddr_vmsa, apic_id, true)?;

    assert!(PERCPU_VMSAS.set_used(paddr_vmsa) == Some(apic_id));
    unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(paddr_vmsa,u64::from(apic_id), 3, params.sev_features | 4)?}
    //this_cpu_mut().ghcb_unsafe().ap_create(paddr_vmsa,u64::from(apic_id), 3, params.sev_features | 4)?;
    log::info!("Run in VMPL3 was successfull");
    log::info!("VMSA host (after execution): \n{:?}", unsafe { SVSM_PERCPU_VMSA_BASE.as_mut_ptr::<VMSA>().as_mut().unwrap() } );
    
    let vmsa_end_res = *vmsa_copy == unsafe { *SVSM_PERCPU_VMSA_BASE.as_mut_ptr::<VMSA>().as_mut().unwrap() };
    log::info!("VMSA comparison: {}", vmsa_end_res);

    return Ok(());

    /* End of Test code */
    /* Start of actual Trustlet creation */
    /*match _t {
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
            Ok(())
        },
        TrustedProcessType::Trustlet => {

            log::info!("create_trusted_process(): Creating and registering Trustlet");
            let len = params.rcx;
            let _trustlet_address = PhysAddr::from(params.r8);
            let trustlet = TrustedProcess::trustlet(ProcessID(params.rdx as usize), PhysAddr::from(params.r8), len);
            if trustlet.process_type == TrustedProcessType::Undefined {
                params.rcx = u64::from_ne_bytes((-1i64).to_ne_bytes());
                return Ok(());
            } 

            let res = PROCESS_STORE.insert(trustlet);
            params.rcx = u64::from_ne_bytes(res.to_ne_bytes());
            Ok(())

        },
    }*/
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