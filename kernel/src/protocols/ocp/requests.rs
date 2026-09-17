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
    mm::ptguards::PerCPUPageMappingGuard,
    protocols::{RequestParams, errors::SvsmReqError},
};

use core::ffi::CStr;

static OCP_OBJECTS: RWLock<Vec<Arc<dyn OcpObject>>> = RWLock::new(Vec::new());

pub fn add_ocp_object(object: Arc<dyn OcpObject>) {
    // todo: check unique name here
    let mut objects = OCP_OBJECTS.lock_write();
    objects.push(object);
}

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
    let mut name_slice = [0u8; OCP_NAME_LEN];
    let name_guard = PerCPUPageMappingGuard::create(
        gpa_obj_name.page_align(),
        gpa_obj_name
            .checked_add(OCP_NAME_LEN)
            .ok_or(SvsmReqError::invalid_address())?
            .page_align_up(),
        0,
    )?;

    let name_ptr = name_guard.guest_slice::<u8>(gpa_obj_name.page_offset(), OCP_NAME_LEN)?;
    name_ptr.read_to_slice(&mut name_slice)?;

    let obj_name = CStr::from_bytes_until_nul(&name_slice)
        .map_err(|_| SvsmReqError::invalid_parameter())?
        .to_str()
        .map_err(|_| SvsmReqError::invalid_parameter())?;

    get_ocp_object(obj_name).ok_or(SvsmReqError::invalid_parameter())
}

/// Retrieve the identifier name from guest memory and extract the corresponding source
fn get_requested_source(gpa_id: PhysAddr) -> Result<Arc<dyn OcpSource>, SvsmReqError> {
    let mut id_slice = [0u8; OCP_IDENTIFIER_LEN];

    let id_guard = PerCPUPageMappingGuard::create(
        gpa_id.page_align(),
        gpa_id
            .checked_add(OCP_IDENTIFIER_LEN)
            .ok_or(SvsmReqError::invalid_address())?
            .page_align_up(),
        0,
    )?;

    let id_ptr = id_guard.guest_slice::<u8>(gpa_id.page_offset(), OCP_IDENTIFIER_LEN)?;
    id_ptr.read_to_slice(&mut id_slice)?;

    let (obj_name, source_name) = CStr::from_bytes_until_nul(&id_slice)
        .map_err(|_| SvsmReqError::invalid_parameter())?
        .to_str()
        .map_err(|_| SvsmReqError::invalid_parameter())?
        .split_once('/')
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
