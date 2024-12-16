// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! Implement functions required to build the TPM 2.0 Reference Implementation
//! libraries.
//! All these functionalities are owned by the SVSM Rust code,
//! so we just need to create wrappers for them.

use crate::{
    console::_print,
    mm::alloc::{layout_from_ptr, layout_from_size},
    sev::msr_protocol::request_termination_msr,
};

use core::{
    ffi::{c_char, c_int, c_ulong, c_void},
    ptr,
    slice::from_raw_parts,
    str::from_utf8,
};

extern crate alloc;
use alloc::alloc::{alloc, alloc_zeroed, dealloc, realloc as _realloc};

#[no_mangle]
pub extern "C" fn malloc(size: c_ulong) -> *mut c_void {
    if let Ok(layout) = layout_from_size(size as usize) {
        return unsafe { alloc(layout).cast() };
    }
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn calloc(items: c_ulong, size: c_ulong) -> *mut c_void {
    if let Some(new_size) = items.checked_mul(size) {
        if let Ok(layout) = layout_from_size(new_size as usize) {
            return unsafe { alloc_zeroed(layout).cast() };
        }
    }
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn realloc(p: *mut c_void, size: c_ulong) -> *mut c_void {
    let ptr = p as *mut u8;
    let new_size = size as usize;

    if p.is_null() {
        return malloc(size);
    }

    if let Some(layout) = layout_from_ptr(ptr) {
        if new_size == 0 {
            // SAFETY: layout_from_ptr() call ensures that `ptr` was allocated
            // with this allocator and we are using the same `layout` used to
            // allocate `ptr`.
            unsafe { dealloc(ptr, layout) };
            return ptr::null_mut();
        }

        return unsafe { _realloc(ptr, layout, new_size).cast() };
    }
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    let ptr = p as *mut u8;
    if let Some(layout) = layout_from_ptr(ptr.cast()) {
        unsafe { dealloc(ptr, layout) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn serial_out(s: *const c_char, size: c_int) {
    let str_slice: &[u8] = unsafe { from_raw_parts(s as *const u8, size as usize) };
    if let Ok(rust_str) = from_utf8(str_slice) {
        _print(format_args!("[SVSM] {}", rust_str));
    } else {
        log::error!("ERR: BUG: serial_out arg1 is not a valid utf8 string");
    }
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    request_termination_msr();
}
