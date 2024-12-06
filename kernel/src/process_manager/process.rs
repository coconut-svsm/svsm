extern crate alloc;

use core::cell::UnsafeCell;
use alloc::vec::Vec;
use igvm_defs::PAGE_SIZE_4K;
use crate::address::PhysAddr;
use crate::cpu::percpu::this_cpu_shared;
use crate::cpu::percpu::this_cpu_unsafe;
use crate::mm::PAGE_SIZE;
use crate::mm::SVSM_PERCPU_VMSA_BASE;
use crate::process_manager::process_memory::allocate_page;
use crate::process_manager::allocation::AllocationRange;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::sev::RMPFlags;
use crate::sev::rmp_adjust;
//use crate::cpu::percpu::this_cpu_mut;
use crate::cpu::percpu::this_cpu;
//use crate::cpu::flush_tlb_global_sync;
use crate::types::PageSize;
use crate::address::VirtAddr;
use crate::mm::PerCPUPageMappingGuard;
use crate::sev::utils::rmp_set_guest_vmsa;
use crate::vaddr_as_u64_slice;

use cpuarch::vmsa::VMSA;
use core::mem::replace;

use super::memory_channels::MemoryChannel;

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
    pub fn insert(&self, mut p: TrustedProcess) -> i64 {
        let ptr: &mut Vec<TrustedProcess> = unsafe { self.processes.get().as_mut().unwrap() };
        for i in 0..(ptr.len()) {
            if ptr[i].process_type == TrustedProcessType::Undefined {
                // ID of the Process is set when inserting into the
                // store. Only after the insert is the process id valid
                p.id = i.try_into().unwrap();
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

#[derive(Clone,Copy,Debug, Default)]
pub struct ProcessID(pub usize);

#[derive(Clone,Copy,Debug)]
pub struct TrustedProcess {
    pub process_type: TrustedProcessType,
    pub id: u64,
    pub base: ProcessBaseContext,
    #[allow(dead_code)]
    pub context: ProcessContext,
    //pub channel: MemoryChannel,
}

impl TrustedProcess {

    pub fn zygote(data: u64,size: u64, pgt: u64) -> Self{

        // The Zygote is loaded in 3 files
        // We first load the a struct/array of addresses
        // that can then be used to get the next parts
        let (zygote_data, range) = ProcessPageTableRef::copy_data_from_guest(data, size, pgt);

        let zygote_data_struct = vaddr_as_u64_slice!(zygote_data);
        let pal = zygote_data_struct[0];
        let pal_size = zygote_data_struct[3];
        let manifest = zygote_data_struct[1];
        let manifest_size = zygote_data_struct[4];
        let libos = zygote_data_struct[2];
        let libos_size= zygote_data_struct[5];


        // The allocation is always starting at the same virtual address which is why only one allocaiton is valid
        // at the same time. TODO: Allow for different start addresses
        let (pal_data, pal_range) = ProcessPageTableRef::copy_data_from_guest(pal, pal_size, pgt);
        let mut base = ProcessBaseContext::default();
        base.init_with_data(pal_data, pal_size, pal_range);
        let (manifest_data, manifest_range) = ProcessPageTableRef::copy_data_from_guest(manifest, manifest_size, pgt);
        base.add_manifest(manifest_data, manifest_size, manifest_range);
        let(libos_data, libos_range) = ProcessPageTableRef::copy_data_from_guest(libos, libos_size, pgt);
        base.add_libos(libos_data, libos_size, libos_range);


        // TODO: Free zygote data
        Self {
            process_type: TrustedProcessType::Zygote,
            id: 0,
            base,
            context: ProcessContext::default(),
        }
    }

    fn dublicate(pid: ProcessID) -> TrustedProcess {
        let process = PROCESS_STORE.get(pid);
        let base: ProcessBaseContext = process.base;
        let mut context = ProcessContext::default();
        context.init(base);

        TrustedProcess {
            process_type: TrustedProcessType::Trustlet,
            id: 0,
            base,
            context,
        }

    }

    pub fn trustlet(parent: ProcessID, data: u64, size: u64, pgt: u64) -> Self{
        // Inherit the data from the Zygote
        let trustlet = TrustedProcess::dublicate(parent);
        if data != 0 {
            let (function_code, function_code_range) = ProcessPageTableRef::copy_data_from_guest(data, size, pgt);
            trustlet.base.page_table_ref.add_function(function_code, size);
            function_code_range.delete();
        }
        trustlet
    }

    pub fn empty() -> Self {
        Self {
            process_type: TrustedProcessType::Undefined,
            id: 0,
            base: ProcessBaseContext::default(),
            context: ProcessContext::default(),
        }
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

pub fn create_trusted_process(params: &mut RequestParams, t: TrustedProcessType) -> Result<(), SvsmReqError>{

    let size = params.rcx;
    let process_addr = params.rdx;
    let guest_pgt = params.r8;

    match t {
        TrustedProcessType::Undefined => panic!("Invalid Creation Request"),
        TrustedProcessType::Zygote => {

            log::info!("create_trusted_process(): Creating and registering Zygote");

            // Create contexts for the Zygote
            // e.g. Copy the Zygote into memory
            // and parse it to create a page table
            let z: TrustedProcess = TrustedProcess::zygote(process_addr, size, guest_pgt);

            // Insert it into the process store
            // Each process is identified with an idea from
            // the store
            let res = PROCESS_STORE.insert(z);

            // Copy the value to the return register
            // Conversion is required because the store
            // id is signed but the register representation
            // is not
            params.rcx = u64::from_ne_bytes(res.to_ne_bytes());
           
            log::info!("Created Zygote #{}", params.rcx);
            Ok(())
        },
        TrustedProcessType::Trustlet => {

            log::info!("create_trusted_process(): Creating and registering Trustlet");

            // We get the Zygote ID from the guest
            // Each Trustlet requires one Zygote
            let zygote_id = ProcessID(params.r9 as usize);


            let trustlet = TrustedProcess::trustlet(zygote_id, process_addr, size, guest_pgt);

            // The creation process might fail
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

pub fn check_page_table(pgd_addr: u64, test_location: u64) {

    log::info!("Using Address: {:#x}", pgd_addr);
    let mut page_table_ref = ProcessPageTableRef::default();
    page_table_ref.set_external_table(pgd_addr);
    log::info!("Trying to print page table");
    //page_table_ref.print_table();
    log::info!("Finding address");
    page_table_ref.copy_address_range(VirtAddr::from(test_location),1,VirtAddr::null());
}

pub fn create_trustlet_page_table_from_user_data(data: VirtAddr, size: u64) -> ProcessPageTableRef {

    log::info!("Trying to create Page Table");
    //Page Table ref for the Trustlet
    let mut page_table_ref = ProcessPageTableRef::default();
    page_table_ref.build_from_file(data, size);

    page_table_ref
}


#[derive(Debug, Copy, Clone)]
pub struct ProcessBaseContext {
    pub page_table_ref: ProcessPageTableRef,
    pub entry_point: VirtAddr,
    pub alloc_range: AllocationRange,
    pub alloc_range_manifest: AllocationRange,
    pub alloc_range_libos: AllocationRange,
}

impl Default for ProcessBaseContext {
  fn default() -> Self {
      return ProcessBaseContext {
          page_table_ref: ProcessPageTableRef::default(),
          entry_point: VirtAddr::null(),
          alloc_range: AllocationRange(0,0),
          alloc_range_manifest: AllocationRange(0,0),
          alloc_range_libos: AllocationRange(0,0),
      }
  }
}

impl ProcessBaseContext {
    pub fn init(&mut self, elf: VirtAddr, size: u64) {
        let mut ptr = ProcessPageTableRef::default();
        self.entry_point = ptr.build_from_file(elf, size);
        self.page_table_ref = ptr;
    }

    pub fn add_manifest(&mut self, manifest: VirtAddr, size: u64, data: AllocationRange) {
        let size = (4096 - (size & 0xFFF)) + size;
        self.page_table_ref.add_manifest(manifest, size);
        self.alloc_range_manifest = data;
    }

    pub fn add_libos(&mut self, manifest: VirtAddr, size: u64, data: AllocationRange){
        let size = (4096 - (size & 0xFFF)) + size;
        self.page_table_ref.add_libos(manifest,size);
        self.alloc_range_libos = data;
    }

    pub fn init_with_data(&mut self, elf: VirtAddr, size: u64, data: AllocationRange) {
        self.init(elf, size);
        self.alloc_range = data;
    }

}

#[derive(Debug, Copy, Clone)]
pub struct ProcessContext {
    pub base: ProcessBaseContext,
    pub vmsa: PhysAddr,
    pub channel: MemoryChannel,
    pub sev_features: u64,
}

impl Default for ProcessContext {
    fn default() -> Self {
        return ProcessContext {
            base: ProcessBaseContext::default(),
            vmsa: PhysAddr::null(),
            channel: MemoryChannel::default(),
            sev_features: 0,
        }
    }
}


impl ProcessContext {

    pub fn init(&mut self, base: ProcessBaseContext) {

        //Creating new VMSA for the Process
        let new_vmsa_page = allocate_page();
        let new_vmsa_mapping = PerCPUPageMappingGuard::create_4k(new_vmsa_page).unwrap();
        let new_vmsa_vaddr = new_vmsa_mapping.virt_addr();

        //Permission Setup for VMSA
        rmp_adjust(new_vmsa_vaddr, RMPFlags::VMPL1 | RMPFlags::RWX, PageSize::Regular).unwrap();
        rmp_set_guest_vmsa(new_vmsa_vaddr).unwrap();
        rmp_adjust(new_vmsa_vaddr, RMPFlags::VMPL1 | RMPFlags::VMSA, PageSize::Regular).unwrap();

        //Guest VMSA -> New VMSA
        let vmsa = VMSA::from_virt_addr(new_vmsa_vaddr);
        let locked = this_cpu_shared().guest_vmsa.lock();
        let old_vmsa_ptr = unsafe { SVSM_PERCPU_VMSA_BASE.as_mut_ptr::<VMSA>().as_mut().unwrap() };
        _ = replace(vmsa, *old_vmsa_ptr);
        drop(locked);

        //New VMSA Setup
        vmsa.vmpl = 1; // Trustlets always run in VMPL1
        vmsa.cpl = 3; // Ring 3
        vmsa.cr3 = u64::from(base.page_table_ref.process_page_table);
        vmsa.efer = vmsa.efer | 1u64 << 12;
        vmsa.rip = base.entry_point.into();
        vmsa.sev_features = old_vmsa_ptr.sev_features | 4; // 4 is for #VC Reflect
        // New Stack
        vmsa.rbp = u64::from(0x8000000000u64)+8*4096-1;
        vmsa.rsp = u64::from(0x8000000000u64)+8*4096-1;

        //Check VMSA
        let svme_mask: u64 = 1u64 << 12;
        if !check_vmsa_ind(vmsa, vmsa.sev_features, svme_mask, RMPFlags::VMPL1.bits()) {
            log::info!("VMSA Check failed");
            log::info!("Bits: {}",vmsa.vmpl == RMPFlags::VMPL1.bits() as u8);
            log::info!("Efer & vsme_mask: {}", vmsa.efer & svme_mask == svme_mask);
            log::info!("SEV features: {}", vmsa.sev_features == vmsa.sev_features);
            panic!("Failed to create new VMSA");
        }


        //Memory Channel setup -- No chain setup here
        let page_table_addr = vmsa.cr3;
        let mut pptr = ProcessPageTableRef::default();
        pptr.set_external_table(page_table_addr);
        self.channel.allocate_input(&mut pptr, PAGE_SIZE);
        self.channel.allocate_output(&mut pptr, PAGE_SIZE);


        self.vmsa = new_vmsa_page;
        self.sev_features = vmsa.sev_features;
        self.base = base;

    }

    pub fn add_function(&mut self, function: VirtAddr, size: u64) {
        let size = size + PAGE_SIZE_4K - (size % PAGE_SIZE_4K);
        self.base.page_table_ref.add_function(function, size);
    }

    pub fn test_run(&self) {
        let apic_id = this_cpu().get_apic_id();
        log::info!("Trying to execute Context");
        unsafe {(*(*this_cpu_unsafe()).ghcb).ap_create(self.vmsa,u64::from(apic_id), 1, self.sev_features | 4).unwrap()}
        log::info!("Done Trying");
        log::info!("Moving RIP");
        let mapping = PerCPUPageMappingGuard::create_4k(self.vmsa).unwrap();
        let vmsa_vaddr = mapping.virt_addr();
        let vmsa = unsafe {vmsa_vaddr.as_mut_ptr::<VMSA>().as_mut().unwrap() };
        let rip = vmsa.rip;
        log::info!("Now: {:?}",rip);
        vmsa.rip = vmsa.rip + 2; //cpuid is 2 Bytes long
    }

}

