// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};

use super::source::OmpObject;
use crate::{
    locking::RWLock,
    protocols::{RequestParams, errors::SvsmReqError},
};

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

pub fn omp_protocol_request(request: u32, _params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        _ => Err(SvsmReqError::unsupported_call()),
    }
}
