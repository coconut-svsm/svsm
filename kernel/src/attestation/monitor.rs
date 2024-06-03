use crate::{address::PhysAddr, greq::services::{get_regular_report, REPORT_RESPONSE_SIZE}};
use crate::greq::pld_report::SnpReportResponse;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::mm::PerCPUPageMappingGuard;

pub fn attest_monitor(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let mut rep: [u8; REPORT_RESPONSE_SIZE] = [0u8;REPORT_RESPONSE_SIZE];

    rep[0] = 1;
    log::info!("Requesting Monitor Attestation Report");
    let rep_size = get_regular_report(&mut rep)?;

    if params.rdx == 0 {
        /* Here we only query for the size of the report */
        params.rdx = rep_size.try_into().unwrap();
        return Ok(());
    }

    params.rdx = rep_size.try_into().unwrap();

    log::info!("Size of Report: {rep_size}");
    let r = SnpReportResponse::try_from_as_ref(&mut rep)?;
    log::info!("Report: {:?}\n",r);
    log::info!("Report: {:?}\n",rep);
    //TODO: Check if address is valid for this request
    let target_address = PhysAddr::from(params.rcx);
    let mapped_target_page = PerCPUPageMappingGuard::create_4k(target_address).unwrap();
    let target = unsafe {mapped_target_page.virt_addr().as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};
    target[0..rep_size].copy_from_slice(&rep);
    
    
    Ok(())
}

