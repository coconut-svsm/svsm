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

pub const APIC_PROTOCOL_VERSION_MIN: u32 = 1;
pub const APIC_PROTOCOL_VERSION_MAX: u32 = 1;

fn apic_query_features(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    // No features are supported beyond the base feature set.
    params.rcx = 0;
    Ok(())
}

fn apic_configure(params: &RequestParams) -> Result<(), SvsmReqError> {
    let enabled = match params.rcx {
        0b00 => {
            // Query the current registration state of APIC emulation to
            // determine whether it should be disabled on the current CPU.
            SVSM_PLATFORM.query_apic_registration_state()
        }

        0b01 => {
            // Deregister APIC emulation if possible, noting whether it is now
            // disabled for the platform.  This cannot fail.
            SVSM_PLATFORM.change_apic_registration_state(false).unwrap()
        }

        0b10 => {
            // Increment the APIC emulation registration count.  If successful,
            // this will not cause any change to the state of the current CPU.
            SVSM_PLATFORM.change_apic_registration_state(true)?;
            return Ok(());
        }

        _ => {
            return Err(SvsmReqError::invalid_parameter());
        }
    };

    // Disable APIC emulation on the current CPU if required.
    if !enabled {
        this_cpu().disable_apic_emulation();
    }

    Ok(())
}

fn apic_read_register(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let cpu = this_cpu();
    let value = cpu.read_apic_register(params.rcx)?;
    params.rdx = value;
    Ok(())
}

fn apic_write_register(params: &RequestParams) -> Result<(), SvsmReqError> {
    let cpu = this_cpu();
    cpu.write_apic_register(params.rcx, params.rdx)?;
    Ok(())
}

fn apic_configure_vector(params: &RequestParams) -> Result<(), SvsmReqError> {
    let cpu = this_cpu();
    if !cpu.use_apic_emulation() {
        return Err(SvsmReqError::invalid_request());
    }
    if params.rcx <= 0x1FF {
        let vector: u8 = (params.rcx & 0xFF) as u8;
        let allowed = (params.rcx & 0x100) != 0;
        cpu.configure_apic_vector(vector, allowed)?;
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
