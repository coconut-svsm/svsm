use crate::{address::PhysAddr, greq::services::{get_regular_report, REPORT_RESPONSE_SIZE}, my_crypto_wrapper::key_pair};
use crate::greq::pld_report::SnpReportResponse;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::mm::PerCPUPageMappingGuard;

/*use crate::my_rsa_wrapper::get_RSA_public_key;
use crate::my_rsa_wrapper::RSA_key;
use crate::my_rsa_wrapper::my_SHA512;
use crate::my_rsa_wrapper::RSA_decrypt;
use crate::my_rsa_wrapper::get_cycles;
*/

extern crate alloc;
use alloc::vec::Vec;

//use crate::my_crypto_wrapper::ENCRYPTION_KEYS;
use crate::my_crypto_wrapper::get_key_size;
use crate::my_crypto_wrapper::my_SHA512;
use crate::my_crypto_wrapper::get_keys;


#[allow(non_snake_case)]
pub fn attest_monitor(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    log::info!("[Doing attest]");
    let mut rep: [u8; REPORT_RESPONSE_SIZE] = [0u8;REPORT_RESPONSE_SIZE];

    // TODO: Change VMPL level before writing hash s.t. guest can't tamper with it

    //let ENCRYPTION_KEYS: key_pair = key_pair::new();
    let mut pub_key: [u8;32] = unsafe{(*get_keys()).public_key};

    /*// OPTIMIZE: This can probably be done a LOOOOOOT more efficiently :)
    let mut raw_key: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < unsafe{get_key_size().try_into().unwrap()} {
        raw_key.push( unsafe{  *((*pub_key).key.offset(i.try_into().unwrap()))  });
        i = i + 1;
    }*/
    
    let mut hash: [u8; 64] = [0; 64];
    let mut n: i32 = unsafe{my_SHA512(pub_key.as_mut_ptr(), pub_key.len().try_into().unwrap(), hash.as_mut_ptr()).try_into().unwrap()};
    log::info!("Raw key: {:?}", pub_key);
    log::info!("SHA returned: {} and a hash of {:?}", n, hash);

    // Include hash in report
    let mut i = 0;
    while i < 64 {
        rep[i] = hash[i];
        i += 1;
    }


    //log::info!("Requesting Monitor Attestation Report");
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

    //log::info!("Size of Report: {rep_size}");
    let r = SnpReportResponse::try_from_as_ref(&mut rep)?;
    //log::info!("Report r: {:?}\n",r);
    //log::info!("Report rep: {:?}\n",rep);
    //TODO: Check if address is valid for this request
    let target_address = PhysAddr::from(params.rcx);
    let mapped_target_page = PerCPUPageMappingGuard::create_4k(target_address).unwrap();
    let target = unsafe {mapped_target_page.virt_addr().as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};
    target[0..rep_size].copy_from_slice(&rep);
    
    
    Ok(())
}

#[allow(non_snake_case)]
pub fn get_public_key(params: &mut RequestParams) -> Result<(), SvsmReqError> {

    log::info!("[Monitor] Getting public key");

    //TODO: Return actual public key
    let ENCRYPTION_KEYS: key_pair = unsafe{*get_keys()};

    let target_address = PhysAddr::from(params.rcx);
    let mapped_target_page = PerCPUPageMappingGuard::create_4k(target_address).unwrap();
    let target = unsafe {mapped_target_page.virt_addr().as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};

    let target_address = PhysAddr::from(params.rcx);
    let mapped_target_page = PerCPUPageMappingGuard::create_4k(target_address).unwrap();
    let target = unsafe {mapped_target_page.virt_addr().as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};

    let mut i: usize = 0;
    while i < 32 {
        target[i] = ENCRYPTION_KEYS.public_key[i];
        i = i + 1;
    }   
    target[32] = 0;
   
  Ok(())  
}

pub fn send_policy(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    //log::info!("[Monitor] Receiveing policy");
    let target_address = PhysAddr::from(params.rcx);
    let mapped_target_page = PerCPUPageMappingGuard::create_4k(target_address).unwrap();
    let target = unsafe {mapped_target_page.virt_addr().as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};

    let mut decrypted: [u8; 256] = [0; 256];

    //let n: i32 = unsafe{RSA_decrypt(256, target.as_mut_ptr(), decrypted.as_mut_ptr())};
    
    Ok(())
}
