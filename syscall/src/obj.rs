// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::call::syscall1;
use super::SYS_CLOSE;

/// The object is exposed to the user mode via the object-opening related
/// syscalls, which returns the id of the object created by the COCONUT-SVSM
/// kernel. The user mode can make use this id to access the corresponding
/// object via other syscalls. From the user mode's point of view, an
/// ObjHanle is defined to wrap a u32 which is the value returned by an
/// object-opening syscall. This u32 value can be used as the input for the
/// syscalls to access the corresponding kernel object.
#[derive(Debug)]
pub struct ObjHandle(u32);

impl ObjHandle {
    pub(crate) fn new(id: u32) -> Self {
        Self(id)
    }
}

impl From<&ObjHandle> for u32 {
    #[inline]
    fn from(obj_handle: &ObjHandle) -> Self {
        obj_handle.0
    }
}

pub trait Obj {
    fn id(&self) -> u32;
}

impl Drop for ObjHandle {
    fn drop(&mut self) {
        // SAFETY: SYS_CLOSE is supported syscall number by the svsm kernel.
        unsafe {
            let _ = syscall1(SYS_CLOSE, self.0.into());
        }
    }
}
