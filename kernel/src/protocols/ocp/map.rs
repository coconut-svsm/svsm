// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::{locking::RWLock, protocols::errors::SvsmReqError};

use super::api::OcpObjectOperations;

static OCP_SOURCES: RWLock<BTreeMap<u32, Arc<dyn OcpObjectOperations>>> =
    RWLock::new(BTreeMap::new());

static FIRST_FREE_INDEX: AtomicU32 = AtomicU32::new(0);

pub fn add_ocp_object(sup_index: u32, source: Arc<dyn OcpObjectOperations>) {
    //todo: return error when index is already taken

    let mut map = OCP_SOURCES.lock_write();

    if map.contains_key(&sup_index) {
        panic!("Super index already defined");
    }

    let _ = map.insert(sup_index, source);
}

pub fn explore_map(
    first: u32,
    count: u32,
) -> Result<Vec<Arc<dyn OcpObjectOperations>>, SvsmReqError> {
    let map = OCP_SOURCES.lock_read();
    if first as usize >= map.len() {
        return Err(SvsmReqError::invalid_parameter());
    }
    Ok(map
        .range(first..)
        .take(count as usize)
        .map(|(_key, obj)| Arc::clone(obj))
        .collect())
}

pub fn get_object(index: u32) -> Option<Arc<dyn OcpObjectOperations>> {
    let map = OCP_SOURCES.lock_read();
    map.get(&index).cloned()
}

pub fn get_first_free_index() -> Option<u32> {
    // At runtime, an index is stable and will not be reused for other
    // sources, so when u32::MAX is reached no more indexes are provided.
    FIRST_FREE_INDEX
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |index| {
            index.checked_add(1)
        })
        .ok()
}
