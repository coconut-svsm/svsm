// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use alloc::{sync::Arc, vec::Vec};

use super::source::OcpObject;
use crate::locking::RWLock;

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
