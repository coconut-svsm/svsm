//use crate::address::PhysAddr;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;
use crate::attestation;
use crate::process_manager::process::TrustedProcessType;

const MONITOR_INIT: u32 = 0;
const ATTEST_MONITOR: u32 = 1;
//const LOAD_POLICY: u32 = 2;
const CREATE_ZYGOTE: u32 = 4;
const DELETE_ZYGOTE: u32 = 5;
const CREATE_TRUSTLET: u32 = 6;
const DELETE_TRUSTLET: u32 = 7;

const GET_PUBLIC_KEY: u32 = 30;

pub fn attest_monitor(params: &mut RequestParams) -> Result<(), SvsmReqError>{
    attestation::monitor::attest_monitor(params)
}
pub fn monitor_init(_params: &mut RequestParams) -> Result<(), SvsmReqError>{

    log::info!("Initilization Monitor");
    super::process::PROCESS_STORE.init(10);
    crate::sp_pagetable::set_ecryption_mask_address_size();
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

pub fn get_public_key(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    attestation::monitor::get_public_key(params)
}

pub fn monitor_call_handler(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        MONITOR_INIT => monitor_init(params),
        ATTEST_MONITOR => attest_monitor(params),
        CREATE_ZYGOTE => create_zygote(params),
        DELETE_ZYGOTE => delete_zygote(params),
        CREATE_TRUSTLET => create_trustlet(params),
        DELETE_TRUSTLET => delete_trustlet(params),
        GET_PUBLIC_KEY => get_public_key(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
