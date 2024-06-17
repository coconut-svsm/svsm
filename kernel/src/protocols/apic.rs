// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::cpu::percpu::this_cpu;
use crate::platform::SVSM_PLATFORM;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;

const SVSM_REQ_APIC_QUERY_FEATURES: u32 = 0;
const SVSM_REQ_APIC_CONFIGURE: u32 = 1;
const SVSM_REQ_APIC_READ_REGISTER: u32 = 2;
const SVSM_REQ_APIC_WRITE_REGISTER: u32 = 3;
const SVSM_REQ_APIC_CONFIGURE_VECTOR: u32 = 4;

const SVSM_APIC_CONFIGURE_DISABLED: u64 = 0;
const SVSM_APIC_CONFIGURE_ENABLED: u64 = 1;
const SVSM_APIC_CONFIGURE_LOCKED: u64 = 2;

pub const APIC_PROTOCOL: u32 = 3;
pub const APIC_PROTOCOL_VERSION_MIN: u32 = 1;
pub const APIC_PROTOCOL_VERSION_MAX: u32 = 1;

const SVSM_ERR_APIC_CANNOT_DISABLE: u64 = 0;
const SVSM_ERR_APIC_CANNOT_LOCK: u64 = 1;

fn apic_query_features(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    // No features are supported beyond the base feature set.
    params.rcx = 0;
    Ok(())
}

fn apic_configure(params: &RequestParams) -> Result<(), SvsmReqError> {
    match params.rcx {
        SVSM_APIC_CONFIGURE_DISABLED => this_cpu()
            .disable_apic_emulation()
            .map_err(|_| SvsmReqError::protocol(SVSM_ERR_APIC_CANNOT_DISABLE)),
        SVSM_APIC_CONFIGURE_ENABLED => {
            // If this fails, the platform is known not to be in the locked
            // state, so any error can be ignored in that case.
            let _ = SVSM_PLATFORM.as_dyn_ref().lock_unlock_apic_emulation(false);
            Ok(())
        }
        SVSM_APIC_CONFIGURE_LOCKED => SVSM_PLATFORM
            .as_dyn_ref()
            .lock_unlock_apic_emulation(false)
            .map_err(|_| SvsmReqError::protocol(SVSM_ERR_APIC_CANNOT_LOCK)),
        _ => Err(SvsmReqError::invalid_parameter()),
    }
}

fn apic_read_register(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let cpu = this_cpu();
    if !cpu.use_apic_emulation() {
        return Err(SvsmReqError::invalid_request());
    }
    let value = cpu
        .read_apic_register(params.rcx)
        .map_err(|_| SvsmReqError::invalid_parameter())?;
    params.rdx = value;
    Ok(())
}

fn apic_write_register(params: &RequestParams) -> Result<(), SvsmReqError> {
    let cpu = this_cpu();
    if !cpu.use_apic_emulation() {
        return Err(SvsmReqError::invalid_request());
    }
    cpu.write_apic_register(params.rcx, params.rdx)
        .map_err(|_| SvsmReqError::invalid_parameter())
}

fn apic_configure_vector(params: &RequestParams) -> Result<(), SvsmReqError> {
    let cpu = this_cpu();
    if params.rcx <= 0x1FF {
        let vector: u8 = (params.rcx & 0xFF) as u8;
        let allowed = (params.rcx & 0x100) != 0;
        cpu.configure_apic_vector(vector, allowed);
        Ok(())
    } else {
        Err(SvsmReqError::invalid_parameter())
    }
}

pub fn apic_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    if !this_cpu().use_apic_emulation() {
        return Err(SvsmReqError::unsupported_protocol());
    }
    match request {
        SVSM_REQ_APIC_QUERY_FEATURES => apic_query_features(params),
        SVSM_REQ_APIC_CONFIGURE => apic_configure(params),
        SVSM_REQ_APIC_READ_REGISTER => apic_read_register(params),
        SVSM_REQ_APIC_WRITE_REGISTER => apic_write_register(params),
        SVSM_REQ_APIC_CONFIGURE_VECTOR => apic_configure_vector(params),

        _ => Err(SvsmReqError::unsupported_call()),
    }
}
