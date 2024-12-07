use crate::{address::PhysAddr, greq::services::{get_regular_report, REPORT_RESPONSE_SIZE} };
use crate::greq::pld_report::{SnpReportResponse, AttestationReport};
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::mm::PerCPUPageMappingGuard;
use core::slice;
extern crate alloc;
use alloc::vec::Vec;
use crate::vaddr_as_u64_slice;

use crate::my_crypto_wrapper::my_SHA512;
use crate::my_crypto_wrapper::get_keys;
use crate::my_crypto_wrapper::decrypt;
use crate::my_crypto_wrapper::key_pair;

use crate::process_manager::PROCESS_STORE;
use crate::process_manager::process::ProcessID;
use crate::process_manager::process_paging::ProcessPageTableRef;
use crate::mm::PAGE_SIZE;

struct StoredSNPReport {
  data: Vec<u8>, // Dynamically sized to hold only the actual report
  size: usize,
}

static mut SNP_REPORT_STORE: Option<StoredSNPReport> = None;

fn store_snp_report(report_data: &[u8], report_size: usize) {
  unsafe {
    SNP_REPORT_STORE = Some(StoredSNPReport {
          data: report_data.to_vec(),
          size: report_size,
      });
  }
}

fn get_snp_report() -> Option<(&'static [u8], usize)> {
  unsafe {
      SNP_REPORT_STORE.as_ref().map(|report| (&report.data[..], report.size))
  }
}

const HASH_SIZE: usize = 64;
const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 24;

const MONITOR_ATTESTATION: u64 = 0;
const ZYGOTE_ATTESTATION: u64 = 1;
const TRUSTLET_ATTESTATION: u64 = 2;
const FUNCTION_ATTESTATION: u64 = 3;

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

fn copy_back_report(report_buffer: u64, report_data: &[u8], report_size: usize) {
  // Ensure the size is within limits to avoid out-of-bounds access
  assert!(report_size <= PAGE_SIZE, "Report size exceeds the allowed page size.");

  let report_address = PhysAddr::from(report_buffer);
  let mapped_report_page = PerCPUPageMappingGuard::create_4k(report_address).unwrap();
  let report = unsafe {
        mapped_report_page.virt_addr()
            .as_mut_ptr::<[u8; PAGE_SIZE]>()
            .as_mut()
            .unwrap()
    };
  report[0..report_size].copy_from_slice(&report_data[0..report_size]);
}

#[allow(non_snake_case)]
fn monitor_report(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    if let Some((stored_report, stored_report_size)) = get_snp_report() {
        // If the report exists, just return it
        log::debug!("Monitor has cached the SNP report");
        copy_back_report(params.rcx, stored_report, stored_report_size);
    } else {
        // The report does not exist so, retrieve and store the Original SNP report
        log::debug!("Monitor retrieves the SNP report");
        let mut rep: [u8; REPORT_RESPONSE_SIZE] = [0; REPORT_RESPONSE_SIZE];

        /* Get a regular report of type struct SnpReportResponse */
        let _rep_struct_size = match get_regular_report(&mut rep) {
            Ok(e) => e,
            Err(e) => {
                log::info!("Error from get report: {:?}", e);
                panic!();
            }
        };

        // Cast the raw bytes into an SnpReportResponse
        let snp_response: &SnpReportResponse = unsafe {
          &*(rep.as_ptr() as *const SnpReportResponse)
        };

        // Check the response for validation
        match snp_response.validate() {
          Ok(e) => e,
          Err(e) => {
              log::info!("Invalid SNP report: {:?}", e);
              panic!();
          }
        };

        let report_size = snp_response.get_report_size() as usize;
        let report = snp_response.get_report();
        log::info!("actual report size { }", snp_response.get_report_size());

        let report_bytes = unsafe {
          core::slice::from_raw_parts(
              (report as *const AttestationReport) as *const u8,
              report_size,
          )
        };

        // Store the report and its size
        store_snp_report(report_bytes, report_size);
        // Return the report
        copy_back_report(params.rcx, report_bytes, report_size);
    }
    Ok(())
}

#[allow(non_snake_case)]
fn zygote_report(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let zygote_id = ProcessID(params.r8 as usize);
    let zygote = PROCESS_STORE.get(zygote_id);

    let init_measurement = zygote.measurements.init_measurement;
    let manifest_measurement = zygote.measurements.manifest_measurement;
    let libos_measurement = zygote.measurements.libos_measurement;

    // Construct the new report
    let mut new_report: Vec<u8> = Vec::new();

    if let Some((existing_report, _existing_report_size)) = get_snp_report() {
        // Copy the existing report data into the new report
        new_report.extend_from_slice(existing_report);
    }
    else {
        log::info!("SNP report is missing");
        panic!();
    }

    // Append the measurements to the new report
    new_report.extend_from_slice(&init_measurement);
    new_report.extend_from_slice(&manifest_measurement);
    new_report.extend_from_slice(&libos_measurement);

    // Now new_report holds the existing report data + measurements
    let new_report_size = new_report.len();

    // Perform the copy_back_report with the new cumulative report
    copy_back_report(params.rcx, &new_report, new_report_size);
    return Ok(());
}

#[allow(non_snake_case)]
fn trustlet_report(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    let trustlet_id = ProcessID(params.r8 as usize);
    let trustlet = PROCESS_STORE.get(trustlet_id);

    let init_measurement = trustlet.measurements.init_measurement;
    let manifest_measurement = trustlet.measurements.manifest_measurement;
    let libos_measurement = trustlet.measurements.libos_measurement;

    // Construct the new report
    let mut new_report: Vec<u8> = Vec::new();

    if let Some((existing_report, _existing_report_size)) = get_snp_report() {
        // Copy the existing report data into the new report
        new_report.extend_from_slice(existing_report);
    }
    else {
        log::info!("SNP report is missing");
        panic!();
    }

    // Append the measurements to the new report
    new_report.extend_from_slice(&init_measurement);
    new_report.extend_from_slice(&manifest_measurement);
    new_report.extend_from_slice(&libos_measurement);

    // Now new_report holds the existing report data + measurements
    let new_report_size = new_report.len();
    log::info!{"zygote report size: { } original size: { }", new_report_size, REPORT_RESPONSE_SIZE};
    // Perform the copy_back_report with the new cumulative report
    copy_back_report(params.rcx, &new_report, new_report_size);
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

    let init_measurement = trustlet.measurements.init_measurement;
    let manifest_measurement = trustlet.measurements.manifest_measurement;
    let libos_measurement = trustlet.measurements.libos_measurement;

    // Get and measure the input data of the function
    let (input_data, _) = ProcessPageTableRef::copy_data_from_guest(fn_input_addr, fn_input_size, guest_pgt);
    let input_hash = measure(input_data.into(), fn_input_size);

    // Get and measure the output data of the function
    let (output_data, _) = ProcessPageTableRef::copy_data_from_guest(fn_output_addr, fn_output_size, guest_pgt);
    let output_hash = measure(output_data.into(), fn_output_size);

    // Construct the new report
    let mut new_report: Vec<u8> = Vec::new();

    if let Some((existing_report, _existing_report_size)) = get_snp_report() {
      // Copy the existing report data into the new report
      new_report.extend_from_slice(existing_report);
    }
    else {
        log::info!("SNP report is missing");
        panic!();
    }

    // Append the measurements to the new report
    new_report.extend_from_slice(&init_measurement);
    new_report.extend_from_slice(&manifest_measurement);
    new_report.extend_from_slice(&libos_measurement);
    new_report.extend_from_slice(&input_hash);
    new_report.extend_from_slice(&output_hash);

    // Now new_report holds the existing report data + measurements
    let new_report_size = new_report.len();
    log::info!{"function report size: { }", new_report_size};
    // Perform the copy_back_report with the new cumulative report
    copy_back_report(params.rcx, &new_report, new_report_size);
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
