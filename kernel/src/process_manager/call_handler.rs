
use crate::cpu::ghcb::current_ghcb;

use crate::error::SvsmError;
use crate::mm::alloc::allocate_zeroed_page;
use crate::mm::memory::get_memory_region_from_map;
use crate::mm::virtualrange::VIRT_ALIGN_4K;
use crate::mm::PerCPUPageMappingGuard;
use crate::address::PhysAddr; 
use crate::mm::PAGE_SIZE;
use crate::process_manager::process_memory::show_page_table;
use crate::protocols::core::core_pvalidate_one;
use crate::sev::ghcb::PageStateChangeOp;
use crate::sev::SevSnpError;
use crate::types::PageSize;
use crate::sev::PvalidateOp;
//use crate::address::PhysAddr;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::errors::SvsmResultCode;
use crate::protocols::RequestParams;
use crate::attestation;
use crate::process_manager::process::TrustedProcessType;
use crate::process_manager::process::vmpl1_init;
use crate::cpu::percpu::this_cpu_mut;
use crate::cpu::percpu::PerCpuUnsafe;
use crate::cpu::percpu::this_cpu_unsafe;
use crate::sev::pvalidate;
use crate::protocols::core::PVALIDATE_LOCK;
use crate::mm::virt_to_phys;

const MONITOR_INIT: u32 = 0;
const ATTEST_MONITOR: u32 = 1;
//const LOAD_POLICY: u32 = 2;
const CREATE_ZYGOTE: u32 = 4;
const DELETE_ZYGOTE: u32 = 5;
const CREATE_TRUSTLET: u32 = 6;
const DELETE_TRUSTLET: u32 = 7;
const INVOKE_TRUSTLET: u32 = 8; 
const ADD_MONITOR_MEMORY: u32 = 10;
const ALLOC_MEMORY: u32 = 20;


pub fn attest_monitor(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    attestation::monitor::attest_monitor(params)
}
/*
pub fn monitor_take_addr(entry: u64, flush: &mut bool) -> Result<(),SvsmReqError> {
    let page_size_bytes = PAGE_SIZE;
    let valign = VIRT_ALIGN_4K;
    let page_size = PageSize::Regular;
    let valid = PvalidateOp::Valid;
    let ign_cf = false;
    let paddr = PhysAddr::from(entry);

    current_ghcb().page_state_change(paddr,paddr + page_size_bytes, PageSize::Regular, PageStateChangeOp::PscPrivate);

    let guard = PerCPUPageMappingGuard::create(paddr, paddr + page_size_bytes, valign)?;
    let vaddr = guard.virt_addr();

    let lock = PVALIDATE_LOCK.lock_read();
    pvalidate(vaddr,page_size,valid).or_else(|err| match err{
        SvsmError::SevSnp(SevSnpError::FAIL_UNCHANGED(_)) if ign_cf => Ok(()),
        _ => Err(err)
    })?;
    drop(lock);
    Ok(())
}*/


pub fn monitor_init(_params: &mut RequestParams) -> Result<(), SvsmReqError>{

    let cpu_unsafe: &mut PerCpuUnsafe = unsafe { this_cpu_unsafe().as_mut().unwrap() };
    let cpu = this_cpu_mut().get_apic_id();
    show_page_table();
    let mut i = 0;

    while i < 3100 {
        let vaddr = allocate_zeroed_page()?;
        log::info!("{}: vaddr: {:#x}, paddr: {:#x}, size: {} kB", i,vaddr,virt_to_phys(vaddr), ((i+1)*4096)/1024);
        i+=1;
    }
    show_page_table();
    return Ok(());
    let region = get_memory_region_from_map(1);
    let size = (region.end() - region.start()) as u64 / 4096;
    let mut i = 0;
    let cbit_pos: u64 = 0x8000000000000u64;
    while size < i {
        //let paddr = PhysAddr::from((0x100000000u64 +(i*4096)) | cbit_pos );
        let paddr = PhysAddr::from(0x100000000u64 +(i*4096));
        let mut flush = false;
        //monitor_take_addr(u64::from(paddr), &mut flush);
        //current_ghcb().page_state_change(paddr, paddr+PAGE_SIZE,PageSize::Regular,PageStateChangeOp::PscPrivate);
        //log::info!("{:?}",region);
        let mapping_guard = PerCPUPageMappingGuard::create_4k(paddr)?;
        let vaddr = mapping_guard.virt_addr();
        //pvalidate(vaddr,PageSize::Regular, PvalidateOp::Valid);
        //let mut test_value: &mut u64 = unsafe { vaddr.as_mut_ptr::<u64>().as_mut().unwrap()};
        //*test_value = i;
        //log::info!("Writting {} to Address: {:x}",test_value, vaddr);
        i+=1;
        if i % 10000 == 0 {
            log::info!("{:x}",i*4096)
        }
        //panic!();
    }
    if cpu_unsafe.is_trustlet_vmsa() {
        
        log::info!("Trustlet vCore #{} already initialized", cpu);
        return Err(SvsmReqError::RequestError(SvsmResultCode::INVALID_REQUEST));
    }
    log::info!("Initilization Monitor on #{}", cpu);
    super::process::PROCESS_STORE.init(10);
    crate::sp_pagetable::set_ecryption_mask_address_size();
    let _ = vmpl1_init();
    log::info!("Initilization Done");
    Ok(())
}

pub fn create_zygote(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    super::process::create_trusted_process(params,TrustedProcessType::Zygote)
}

pub fn delete_zygote(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::process::delete_trusted_process(params)
}

pub fn create_trustlet(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::process::create_trusted_process(params, TrustedProcessType::Trustlet)
}

pub fn delete_trustlet(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::process::delete_trusted_process(params)
}

pub fn invoke_trustlet(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::process::invoke_trustlet(params)
}

/*
pub fn allocate_memory(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::process_memory::allocate_memory(params)
}

pub fn add_monitor_memory(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    super::process_memory::add_monitor_memory(params)
} */

pub fn monitor_call_handler(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    log::info!("request: {}",request);
    match request {
        MONITOR_INIT => monitor_init(params),
        ATTEST_MONITOR => attest_monitor(params),
        CREATE_ZYGOTE => create_zygote(params),
        DELETE_ZYGOTE => delete_zygote(params),
        CREATE_TRUSTLET => create_trustlet(params),
        DELETE_TRUSTLET => delete_trustlet(params),
        INVOKE_TRUSTLET => invoke_trustlet(params),
        //ALLOC_MEMORY => allocate_memory(params),
        //ADD_MONITOR_MEMORY => add_monitor_memory(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
