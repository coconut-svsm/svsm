// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};

use super::source::{OCP_IDENTIFIER_LEN, OCP_NAME_LEN, OcpObject, OcpSource};
use crate::{
    address::{Address, PhysAddr},
    locking::RWLock,
    mm::guestmem::read_from_guest,
    protocols::{RequestParams, errors::SvsmReqError},
};

use core::ffi::CStr;

static OCP_OBJECTS: RWLock<Vec<Arc<dyn OcpObject>>> = RWLock::new(Vec::new());

/// Adds an OCP object to the global list if there is not already one with the same name.
pub fn add_ocp_object(object: Arc<dyn OcpObject>) -> bool {
    let new_obj_name = object.get_name();
    let mut objects = OCP_OBJECTS.lock_write();
    for obj in objects.iter() {
        if obj.get_name() == new_obj_name {
            return false;
        }
    }
    objects.push(object);
    true
}

/// Returns the OCP object with the given name, if it exists.
pub fn get_ocp_object(name: &str) -> Option<Arc<dyn OcpObject>> {
    let objects = OCP_OBJECTS.lock_read();
    for obj in objects.iter() {
        if obj.get_name() == name {
            return Some(obj.clone());
        }
    }
    None
}

/// Retrieve the object name from guest memory and extract the corresponding object
fn get_requested_object(gpa_obj_name: PhysAddr) -> Result<Arc<dyn OcpObject>, SvsmReqError> {
    let name_slice = read_from_guest::<[u8; OCP_NAME_LEN]>(gpa_obj_name)?;

    let obj_name = CStr::from_bytes_until_nul(&name_slice)
        .ok()
        .and_then(|s| s.to_str().ok())
        .ok_or(SvsmReqError::invalid_parameter())?;

    get_ocp_object(obj_name).ok_or(SvsmReqError::invalid_parameter())
}

/// Retrieve the identifier name from guest memory and extract the corresponding source
fn get_requested_source(gpa_id: PhysAddr) -> Result<Arc<dyn OcpSource>, SvsmReqError> {
    let id_slice = read_from_guest::<[u8; OCP_IDENTIFIER_LEN]>(gpa_id)?;

    let (obj_name, source_name) = CStr::from_bytes_until_nul(&id_slice)
        .ok()
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.split_once('/'))
        .ok_or(SvsmReqError::invalid_parameter())?;

    let Some(object) = get_ocp_object(obj_name) else {
        return Err(SvsmReqError::invalid_parameter());
    };

    object
        .get_source(source_name)
        .ok_or(SvsmReqError::invalid_parameter())
}

pub fn ocp_protocol_request(request: u32, _params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
