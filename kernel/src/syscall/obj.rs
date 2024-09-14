// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

/// An object represents the type of resource like file, VM, vCPU in the
/// COCONUT-SVSM kernel which can be accessible by the user mode. The Obj
/// trait is defined for such type of resource, which can be used to define
/// the common functionalities of the objects. With the trait bounds of Send
/// and Sync, the objects implementing Obj trait could be sent to another
/// thread and shared between threads safely.
pub trait Obj: Send + Sync + core::fmt::Debug {}

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
