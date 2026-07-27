// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};

use super::source::OcpObject;
use crate::{
    locking::RWLock,
    protocols::{RequestParams, errors::SvsmReqError},
};

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

pub fn ocp_protocol_request(request: u32, _params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
