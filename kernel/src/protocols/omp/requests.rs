// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};

use super::source::{OMP_IDENTIFIER_LEN, OMP_NAME_LEN, OmpObject, OmpSource};
use crate::{
    address::{Address, PhysAddr},
    locking::RWLock,
    mm::guestmem::read_from_guest,
    protocols::{RequestParams, errors::SvsmReqError},
};

use core::ffi::CStr;

static OMP_OBJECTS: RWLock<Vec<Arc<dyn OmpObject>>> = RWLock::new(Vec::new());

/// Adds an OMP object to the global list if there is not already one with the same name.
pub fn add_omp_object(object: Arc<dyn OmpObject>) -> bool {
    let new_obj_name = object.get_name();
    let mut objects = OMP_OBJECTS.lock_write();
    for obj in objects.iter() {
        if obj.get_name() == new_obj_name {
            return false;
        }
    }
    objects.push(object);
    true
}

/// Returns the OMP object with the given name, if it exists.
pub fn get_omp_object(name: &str) -> Option<Arc<dyn OmpObject>> {
    let objects = OMP_OBJECTS.lock_read();
    for obj in objects.iter() {
        if obj.get_name() == name {
            return Some(obj.clone());
        }
    }
    None
}

/// Retrieve the object name from guest memory and extract the corresponding object
fn get_requested_object(gpa_obj_name: PhysAddr) -> Result<Arc<dyn OmpObject>, SvsmReqError> {
    let name_slice = read_from_guest::<[u8; OMP_NAME_LEN]>(gpa_obj_name)?;

    let obj_name = CStr::from_bytes_until_nul(&name_slice)
        .ok()
        .and_then(|s| s.to_str().ok())
        .ok_or(SvsmReqError::invalid_parameter())?;

    get_omp_object(obj_name).ok_or(SvsmReqError::invalid_parameter())
}

/// Retrieve the identifier name from guest memory and extract the corresponding source
fn get_requested_source(gpa_id: PhysAddr) -> Result<Arc<dyn OmpSource>, SvsmReqError> {
    let id_slice = read_from_guest::<[u8; OMP_IDENTIFIER_LEN]>(gpa_id)?;

    let (obj_name, source_name) = CStr::from_bytes_until_nul(&id_slice)
        .ok()
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.split_once('/'))
        .ok_or(SvsmReqError::invalid_parameter())?;

    let Some(object) = get_omp_object(obj_name) else {
        return Err(SvsmReqError::invalid_parameter());
    };

    object
        .get_source(source_name)
        .ok_or(SvsmReqError::invalid_parameter())
}

pub fn omp_protocol_request(request: u32, _params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
