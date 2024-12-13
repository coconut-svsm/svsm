// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

extern crate alloc;

use crate::cpu::percpu::current_task;
use crate::error::SvsmError;
use crate::fs::FsObj;
use alloc::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub enum ObjError {
    InvalidHandle,
    NotFound,
    Busy,
}

/// An object represents the type of resource like file, VM, vCPU in the
/// COCONUT-SVSM kernel which can be accessible by the user mode. The Obj
/// trait is defined for such type of resource, which can be used to define
/// the common functionalities of the objects. With the trait bounds of Send
/// and Sync, the objects implementing Obj trait could be sent to another
/// thread and shared between threads safely.
pub trait Obj: Send + Sync + core::fmt::Debug {
    fn as_fs(&self) -> Option<&FsObj> {
        None
    }
}

/// ObjHandle is a unique identifier for an object in the current process.
/// An ObjHandle can be converted to a u32 id which can be used by the user
/// mode to access this object. The passed id from the user mode by syscalls
/// can be converted to an `ObjHandle`, which is used to access the object in
/// the COCONUT-SVSM kernel.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObjHandle(u32);

impl ObjHandle {
    pub fn new(id: u32) -> Self {
        Self(id)
    }
}

impl From<u32> for ObjHandle {
    #[inline]
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl From<ObjHandle> for u32 {
    #[inline]
    fn from(obj_handle: ObjHandle) -> Self {
        obj_handle.0
    }
}

/// Add an object to the current process and assigns it an `ObjHandle`.
///
/// # Arguments
///
/// * `obj` - An `Arc<dyn Obj>` representing the object to be added.
///
/// # Returns
///
/// * `Result<ObjHandle, SvsmError>` - Returns the object handle of the
///   added object if successful, or an `SvsmError` on failure.
///
/// # Errors
///
/// This function will return an error if adding the object to the
/// current task fails.
pub fn obj_add(obj: Arc<dyn Obj>) -> Result<ObjHandle, SvsmError> {
    current_task().add_obj(obj)
}

/// Closes an object identified by its ObjHandle.
///
/// # Arguments
///
/// * `id` - The ObjHandle for the object to be closed.
///
/// # Returns
///
/// * `Result<Arc<dyn Obj>>, SvsmError>` - Returns the `Arc<dyn Obj>`
///   on success, or an `SvsmError` on failure.
///
/// # Errors
///
/// This function will return an error if removing the object from the
/// current task fails.
pub fn obj_close(id: ObjHandle) -> Result<Arc<dyn Obj>, SvsmError> {
    current_task().remove_obj(id)
}

/// Retrieves an object by its ObjHandle.
///
/// # Arguments
///
/// * `id` - The ObjHandle for the object to be retrieved.
///
/// # Returns
///
/// * `Result<Arc<dyn Obj>>, SvsmError>` - Returns the `Arc<dyn Obj>` on
///   success, or an `SvsmError` on failure.
///
/// # Errors
///
/// This function will return an error if retrieving the object from the
/// current task fails.
pub fn obj_get(id: ObjHandle) -> Result<Arc<dyn Obj>, SvsmError> {
    current_task().get_obj(id)
}
