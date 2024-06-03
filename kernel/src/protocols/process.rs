#![allow(unused_imports)]
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::percpu::{this_cpu_shared, PERCPU_AREAS, PERCPU_VMSAS};
use crate::cpu::vmsa::{vmsa_mut_ref_from_vaddr, vmsa_ref_from_vaddr};
use crate::greq::pld_report::{AttestationReport, SnpReportResponse};
use crate::greq::services::{get_extended_report, get_regular_report, REPORT_RESPONSE_SIZE};
use crate::locking::RWLock;
use crate::mm::virtualrange::{VIRT_ALIGN_2M, VIRT_ALIGN_4K};
use crate::mm::PerCPUPageMappingGuard;
use crate::mm::{valid_phys_address, writable_phys_addr, GuestPtr};
use crate::{attestation, println, process_manager};
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::requests::SvsmCaa;
use crate::sev::utils::{
    pvalidate, rmp_clear_guest_vmsa, rmp_grant_guest_access, rmp_revoke_guest_access,
    rmp_set_guest_vmsa, PvalidateOp, RMPFlags, SevSnpError,
};
use crate::types::{PageSize, PAGE_SIZE, PAGE_SIZE_2M};
use crate::utils::zero_mem_region;
use cpuarch::vmsa::VMSA;




pub fn process_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    process_manager::call_handler::monitor_call_handler(request, params)
}
