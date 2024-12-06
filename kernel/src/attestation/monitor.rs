use crate::{address::PhysAddr, greq::services::{get_regular_report, REPORT_RESPONSE_SIZE} };
use crate::greq::pld_report::SnpReportResponse;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::mm::PerCPUPageMappingGuard;
use core::slice;
use crate::vaddr_as_u64_slice;

use crate::my_crypto_wrapper::my_SHA512;
use crate::my_crypto_wrapper::get_keys;
use crate::my_crypto_wrapper::decrypt;
use crate::my_crypto_wrapper::key_pair;

use crate::process_manager::PROCESS_STORE;
use crate::process_manager::process::ProcessID;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::mm::PAGE_SIZE;

const HASH_SIZE: usize = 64;
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;

const MONITOR_ATTESTATION: u64 = 0;
const ZYGOTE_ATTESTATION: u64 = 1;
const TRUSTLET_ATTESTATION: u64 = 2;
const FUNCTION_ATTESTATION: u64 = 3;

#[repr(C, packed)]
struct FunctionData {
    trustlet_id: u64,
    fn_input_size: u64,
    fn_input_addr: usize,
    fn_output_size: u64,
    fn_output_addr: usize,
}

#[derive(Debug, Copy, Clone)]
pub struct ProcessMeasurements {
    pub init_measurement: [u8; 64],
    pub manifest_measurement: [u8; 64],
    pub libos_measurement: [u8; 64],
}

impl Default for ProcessMeasurements {
    fn default() -> Self {
        return ProcessMeasurements {
            init_measurement: [0; HASH_SIZE],
            manifest_measurement: [0; HASH_SIZE],
            libos_measurement: [0; HASH_SIZE],
        }
    }
}

#[allow(non_snake_case)]
pub fn measure(start_address: u64, size: u64) -> [u8; HASH_SIZE] {

    // Unsafe part: ensure the memory region is accessible and valid
    let region = unsafe {
        core::slice::from_raw_parts(start_address as *const u8, size as usize)
    };
    log::debug!("[Measure] Region address {:p} and len { }", region, region.len());

    let mut hash: [u8; HASH_SIZE] = [0; HASH_SIZE];
    // Get the hash using SHA-512 over the entire memory region
    unsafe {
        my_SHA512(
            region.as_ptr() as *mut u8,
            region.len().try_into().unwrap(),
            hash.as_mut_ptr(),
        );
    }

    // Return the final hash measurement
    hash
}

#[allow(non_snake_case)]
fn monitor_report(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    return Ok(());
    // Original SNP report buffer
    let mut rep: [u8; REPORT_RESPONSE_SIZE] = [0; REPORT_RESPONSE_SIZE];

    // TODO: Change VMPL level before writing hash s.t. guest can't tamper with it
    let mut pub_key: [u8; 32] = unsafe{(*get_keys()).public_key};
    let mut hash: [u8; 64] = [0; 64];
    let _n: i32 = unsafe{my_SHA512(pub_key.as_mut_ptr(), pub_key.len().try_into().unwrap(), hash.as_mut_ptr()).try_into().unwrap()};

    // Include hash in report
    let mut i = 0;
    while i < HASH_SIZE {
        rep[i] = hash[i];
        i += 1;
    }

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

    let _r = SnpReportResponse::try_from_as_ref(&mut rep)?;

    let target_address = PhysAddr::from(params.rcx);
    let mapped_target_page = PerCPUPageMappingGuard::create_4k(target_address).unwrap();
    let target = unsafe {mapped_target_page.virt_addr().as_mut_ptr::<[u8;PAGE_SIZE]>().as_mut().unwrap()};
    target[0..rep_size].copy_from_slice(&rep);
}

#[allow(non_snake_case)]
fn zygote_report(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let zygote_id = ProcessID(params.r8 as usize);
    let zygote = PROCESS_STORE.get(zygote_id);

    let init_measurement = zygote.measurements.init_measurement;
    let manifest_measurement = zygote.measurements.manifest_measurement;
    let libos_measurement = zygote.measurements.libos_measurement;
    // let mut i = 0;
    // while i < HASH_SIZE {
    //     log::info!("{:02x} | {:02x} | {:02x}", init_measurement[i], manifest_measurement[i], libos_measurement[i]);
    //     i += 1;
    // }

    return Ok(());
}

#[allow(non_snake_case)]
fn trustlet_report(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let trustlet_id = ProcessID(params.r8 as usize);
    let trustlet = PROCESS_STORE.get(trustlet_id);

    let init_measurement = trustlet.measurements.init_measurement;
    let manifest_measurement = trustlet.measurements.manifest_measurement;
    let libos_measurement = trustlet.measurements.libos_measurement;
    // let mut i = 0;
    // while i < HASH_SIZE {
    //   log::info!("{:02x} | {:02x} | {:02x}", init_measurement[i], manifest_measurement[i], libos_measurement[i]);
    //   i += 1;
    // }

    return Ok(());
}

#[allow(non_snake_case)]
fn function_report(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let guest_pgt = params.r8;
    let size = PAGE_SIZE;
    let function_data_addr = params.r9;
    let (function_data, _) = ProcessPageTableRef::copy_data_from_guest(function_data_addr, (size).try_into().unwrap(), guest_pgt);

    // Extract the parameters from the struct
    let function_data_struct = vaddr_as_u64_slice!(function_data);
    let trustlet_id = function_data_struct[0];
    let fn_input_size = function_data_struct[1];
    let fn_input_addr = function_data_struct[2];
    let fn_output_size = function_data_struct[3];
    let fn_output_addr = function_data_struct[4];
    log::debug!("Extracted values { } { } { } { } { }", trustlet_id, fn_input_size, fn_input_addr, fn_output_size, fn_output_addr);

    // Get the parent process of the function
    let trustlet_id = ProcessID(trustlet_id as usize);
    let trustlet = PROCESS_STORE.get(trustlet_id);

    // Get and measure the input data of the function
    let (input_data, _) = ProcessPageTableRef::copy_data_from_guest(fn_input_addr, fn_input_size, guest_pgt);
    let input_hash = measure(input_data.into(), fn_input_size);

    // Get and measure the output data of the function
    let (output_data, _) = ProcessPageTableRef::copy_data_from_guest(fn_output_addr, fn_output_size, guest_pgt);
    let output_hash = measure(output_data.into(), fn_output_size);

    // produce_differential_report(trustlet, input_hash, output_hash);
    return Ok(());
}

#[allow(non_snake_case)]
pub fn diff_attestation(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    match params.rdx {
        MONITOR_ATTESTATION => {
            log::info!("[Performing monitor attestation]");
            let _ = monitor_report(params);
        }
        ZYGOTE_ATTESTATION => {
            log::info!("[Performing zygote {} attestation]", params.r8);
            let _ = zygote_report(params);
        }
        TRUSTLET_ATTESTATION => {
            log::info!("[Performing trustlet {} attestation]", params.r8);
            let _ = trustlet_report(params);
        }
        FUNCTION_ATTESTATION => {
            log::info!("[Performing function attestation]");
            let _ = function_report(params);
        }
        _ => {
            log::info!("[Unknown attestation request type]");
        }
    }
    return Ok(());
}

#[allow(non_snake_case)]
pub fn get_public_key(params: &mut RequestParams) -> Result<(), SvsmReqError> {

    //log::info!("[Monitor] Getting public key");

    let encryption_keys: key_pair = unsafe{*get_keys()};

    let target_address = PhysAddr::from(params.rcx);
    let mapped_target_page = PerCPUPageMappingGuard::create_4k(target_address).unwrap();
    let target = unsafe {mapped_target_page.virt_addr().as_mut_ptr::<[u8;PAGE_SIZE]>().as_mut().unwrap()};

    let mut i: usize = 0;
    while i < KEY_SIZE {
        target[i] = encryption_keys.public_key[i];
        i = i + 1;
    }   
    target[KEY_SIZE] = 0;
   
  Ok(())  
}

pub fn exec_elf(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    // TODO: Get the PA of the 2 pages, copy contents 2 contiguous array.
    // Use the ELF read functions on the array and inspect the results
    // See how to execute the ELF. Modify a register and read it from monitor to verify program
    // execution
    // Create a nicer API for transfering ELF files to monitor.
    log::info!("Monitor received elf");
    let page1_address = PhysAddr::from(params.r8);
    let page1 = PerCPUPageMappingGuard::create_4k(page1_address).unwrap();
    let page1_data = unsafe {page1.virt_addr().as_mut_ptr::<[u8;PAGE_SIZE]>().as_mut().unwrap()};

    let page2_address = PhysAddr::from(params.rcx);
    let page2 = PerCPUPageMappingGuard::create_4k(page2_address).unwrap();
    let page2_data = unsafe {page2.virt_addr().as_mut_ptr::<[u8;PAGE_SIZE]>().as_mut().unwrap()};

    let elf_size : u32 = params.rdx.try_into().unwrap();

    log::info!("[Monitor] Elf size: {}", elf_size);

    //copy elf in contiguous array
    let mut elf_raw_data : [u8; PAGE_SIZE * 2] = [0; PAGE_SIZE * 2];

    let mut i = 0;
    while i < PAGE_SIZE {
        elf_raw_data[i] = page1_data[i];
        elf_raw_data[i + PAGE_SIZE] = page2_data[i];
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
    let encrypted_data = unsafe {mapped_enc_data_page.virt_addr().as_mut_ptr::<[u8;PAGE_SIZE]>().as_mut().unwrap()};

    let sender_pub_key_address = PhysAddr::from(params.rcx);
    let mapped_sender_pub_key_page = PerCPUPageMappingGuard::create_4k(sender_pub_key_address).unwrap();
    let sender_pub_key = unsafe {mapped_sender_pub_key_page.virt_addr().as_mut_ptr::<[u8;32]>().as_mut().unwrap()};

    let encrypted_data_size: u32 = params.rdx.try_into().unwrap();
    let mut decrypted: [u8; PAGE_SIZE] = [0; PAGE_SIZE];

    let mut nonce: [u8; NONCE_SIZE] = [0; NONCE_SIZE];
    let _n: u32 = unsafe{decrypt(decrypted.as_mut_ptr(), encrypted_data.as_mut_ptr(),
                                encrypted_data_size , nonce.as_mut_ptr(),
                                sender_pub_key.as_mut_ptr(), (*get_keys()).private_key.as_mut_ptr())};
    Ok(())
}
