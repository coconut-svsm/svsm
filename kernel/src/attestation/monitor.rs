use crate::{address::PhysAddr, greq::services::{get_regular_report, REPORT_RESPONSE_SIZE}};
use crate::greq::pld_report::SnpReportResponse;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::mm::PerCPUPageMappingGuard;

use crate::my_rsa_wrapper::get_RSA_public_key;
use crate::my_rsa_wrapper::RSA_key;
use crate::my_rsa_wrapper::my_SHA512;
use crate::my_rsa_wrapper::RSA_decrypt;

extern crate alloc;
use alloc::vec::Vec;

pub fn attest_monitor(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let mut rep: [u8; REPORT_RESPONSE_SIZE] = [0u8;REPORT_RESPONSE_SIZE];

    // TODO: Change VMPL level before writing hash s.t. guest can't tamper with it

    let pub_key: *mut RSA_key = unsafe{get_RSA_public_key()};
    log::info!("Size from struct: {:?}", unsafe{(*pub_key).size});

    // OPTIMIZE: This can probably be done a LOOOOOOT more efficiently :)
    let mut raw_key: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < unsafe{(*pub_key).size.try_into().unwrap()} {
        raw_key.push( unsafe{  *((*pub_key).key.offset(i.try_into().unwrap()))  });
        i = i + 1;
    }
    
    let mut hash: [u8; 64] = [0; 64];
    let mut n: i32 = unsafe{my_SHA512(raw_key.as_mut_ptr(), raw_key.len().try_into().unwrap(), hash.as_mut_ptr()).try_into().unwrap()};
    log::info!("Raw key: {:?}", raw_key);
    log::info!("SHA returned: {} and a hash of {:?}", n, hash);

    // Include hash in report
    let mut i = 0;
    while i < 64 {
        rep[i] = hash[i];
        i += 1;
    }


    log::info!("Requesting Monitor Attestation Report");
    //let rep_size = get_regular_report(&mut rep)?;
    let rep_size = match get_regular_report(&mut rep) {
    Ok(e) => e,
    Err(e) => {log::info!("Error from get report: {:?}", e); panic!(); }
    };

    if params.rdx == 0 {
        /* Here we only query for the size of the report */
        params.rdx = rep_size.try_into().unwrap();
        return Ok(());
    }

    params.rdx = rep_size.try_into().unwrap();

    log::info!("Size of Report: {rep_size}");
    let r = SnpReportResponse::try_from_as_ref(&mut rep)?;
    log::info!("Report r: {:?}\n",r);
    log::info!("Report rep: {:?}\n",rep);
    //TODO: Check if address is valid for this request
    let target_address = PhysAddr::from(params.rcx);
    let mapped_target_page = PerCPUPageMappingGuard::create_4k(target_address).unwrap();
    let target = unsafe {mapped_target_page.virt_addr().as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};
    target[0..rep_size].copy_from_slice(&rep);
    
    
    Ok(())
}

pub fn get_public_key(params: &mut RequestParams) -> Result<(), SvsmReqError> {

    log::info!("[Monitor] Getting public key");
    let pub_key: *mut RSA_key = unsafe{get_RSA_public_key()};
    let key_size: usize = unsafe{(*pub_key).size.try_into().unwrap()};
    log::info!("Size from struct: {:?}", key_size);

    if key_size >= 4096 {
        log::info!("For now we assume that the public key fits in a page.");
        return Err(SvsmReqError::invalid_request());
    }

    let target_address = PhysAddr::from(params.rcx);
    let mapped_target_page = PerCPUPageMappingGuard::create_4k(target_address).unwrap();
    let target = unsafe {mapped_target_page.virt_addr().as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};

    let mut i: usize = 0;
    while i < key_size {
        target[i] = unsafe{  *((*pub_key).key.offset(i.try_into().unwrap()))  };
        i = i + 1;
    }   
    target[key_size] = 0;
   
  Ok(())  
}

pub fn send_policy(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    log::info!("[Monitor] Receiveing policy");
    let target_address = PhysAddr::from(params.rcx);
    let mapped_target_page = PerCPUPageMappingGuard::create_4k(target_address).unwrap();
    let target = unsafe {mapped_target_page.virt_addr().as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};

    let mut decrypted: [u8; 256] = [0; 256];

    //log::info!("From: {:?}", from);
    //log::info!("To: {:?}", to);
    //log::info!("Encrypting...");
    //n = unsafe{RSA_encrypt(10, from.as_mut_ptr(), to.as_mut_ptr())};
    //log::info!("To: {:?}", to);
    //log::info!("Ecrypted stuff: {}", n);
    let n = unsafe{RSA_decrypt(256, target.as_mut_ptr(), decrypted.as_mut_ptr())};
    log::info!("N: {}, Decrypted: {:?}", n, decrypted);
    let n = unsafe{RSA_decrypt(256, target.as_mut_ptr().add(256), decrypted.as_mut_ptr())};
    log::info!("N: {}, Decrypted: {:?}", n, decrypted);


    
    Ok(())
}
