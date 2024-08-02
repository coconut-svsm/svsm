use crate::{address::PhysAddr, greq::services::{get_regular_report, REPORT_RESPONSE_SIZE} };
use crate::greq::pld_report::SnpReportResponse;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::mm::PerCPUPageMappingGuard;
use core::slice;
extern crate alloc;
use alloc::vec::Vec;

use crate::my_crypto_wrapper::get_key_size;
use crate::my_crypto_wrapper::my_SHA512;
use crate::my_crypto_wrapper::get_keys;
use crate::my_crypto_wrapper::get_cycles;
use crate::my_crypto_wrapper::decrypt;
use crate::my_crypto_wrapper::key_pair;


#[allow(non_snake_case)]
pub fn attest_monitor(params: &mut RequestParams) -> Result<(), SvsmReqError>{
   // log::info!("[Doing attest]");
    let mut rep: [u8; REPORT_RESPONSE_SIZE] = [0u8;REPORT_RESPONSE_SIZE];

    // TODO: Change VMPL level before writing hash s.t. guest can't tamper with it
    let mut pub_key: [u8;32] = unsafe{(*get_keys()).public_key};
    let mut hash: [u8; 64] = [0; 64];
    let mut n: i32 = unsafe{my_SHA512(pub_key.as_mut_ptr(), pub_key.len().try_into().unwrap(), hash.as_mut_ptr()).try_into().unwrap()};
 //   log::info!("Raw key: {:?}", pub_key);
 //   log::info!("SHA returned: {} and a hash of {:?}", n, hash);

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

    //log::info!("[Monitor] Getting public key");

    let encryption_keys: key_pair = unsafe{*get_keys()};

    let target_address = PhysAddr::from(params.rcx);
    let mapped_target_page = PerCPUPageMappingGuard::create_4k(target_address).unwrap();
    let target = unsafe {mapped_target_page.virt_addr().as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};

    let mut i: usize = 0;
    while i < 32 {
        target[i] = encryption_keys.public_key[i];
        i = i + 1;
    }   
    target[32] = 0;
   
  Ok(())  
}

pub fn exec_elf(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    //TODO: Get the PA of the 2 pages, copy contents 2 contiguous array.
    // Use the ELF read functions on the array and inspect the results
    // See how to execute the ELF. Modify a register and read it from monitor to verify program
    // execution
    // Create a nicer API for transfering ELF files to monitor.
    log::info!("Monitor received elf");
    let page1_address = PhysAddr::from(params.r8);
    let page1 = PerCPUPageMappingGuard::create_4k(page1_address).unwrap();
    let page1_data = unsafe {page1.virt_addr().as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};

    let page2_address = PhysAddr::from(params.rcx);
    let page2 = PerCPUPageMappingGuard::create_4k(page2_address).unwrap();
    let page2_data = unsafe {page2.virt_addr().as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};

    let elf_size : u32 = params.rdx.try_into().unwrap();

    log::info!("[Monitor] Elf size: {}", elf_size);

    //copy elf in contiguous array
    let mut elf_raw_data : [u8; 4096 * 2] = [0; 4096 * 2];

    let mut i = 0;
    while i < 4096 {
        elf_raw_data[i] = page1_data[i];
        elf_raw_data[i + 4096] = page2_data[i];
        i = i + 1;
    }

    let elf_buf = unsafe { slice::from_raw_parts(elf_raw_data.as_ptr(), elf_size.try_into().unwrap()) };
    let elf = match elf::Elf64File::read(elf_buf) {
        Ok(elf) => elf,
        Err(e) => panic!("error reading ELF: {}", e),
    };

    log::info!("Elf file: {:?}", elf);

    Ok(())
}

// TODO: For now monitor just receives the policy here and decrypts it. Probablly want to do more with it!
pub fn send_policy(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    log::info!("[Monitor] Receiveing policy");
    let encrypted_data_address = PhysAddr::from(params.r8);
    let mapped_enc_data_page = PerCPUPageMappingGuard::create_4k(encrypted_data_address).unwrap();
    let encrypted_data = unsafe {mapped_enc_data_page.virt_addr().as_mut_ptr::<[u8;4096]>().as_mut().unwrap()};

    let sender_pub_key_address = PhysAddr::from(params.rcx);
    let mapped_sender_pub_key_page = PerCPUPageMappingGuard::create_4k(sender_pub_key_address).unwrap();
    let sender_pub_key = unsafe {mapped_sender_pub_key_page.virt_addr().as_mut_ptr::<[u8;32]>().as_mut().unwrap()};

    let encrypted_data_size: u32 = params.rdx.try_into().unwrap();
    let mut decrypted: [u8; 4096] = [0; 4096];

    let mut nonce: [u8; 24] = [0; 24];
//    let initial_time = unsafe{get_cycles()};
    let n: u32 = unsafe{decrypt(decrypted.as_mut_ptr(), encrypted_data.as_mut_ptr(), encrypted_data_size , nonce.as_mut_ptr(), sender_pub_key.as_mut_ptr(), (*get_keys()).private_key.as_mut_ptr())};
 //   let final_time = unsafe{get_cycles()};
    //log::info!("Total cycles for decryption: {}", final_time - initial_time);
    //log::info!("Sender pub key: {:?}", sender_pub_key);
    //log::info!("Encrypted data: {:?}", encrypted_data);
    //log::info!("Decryption:{} Bytes: {:?}", n, decrypted);

    Ok(())
}
