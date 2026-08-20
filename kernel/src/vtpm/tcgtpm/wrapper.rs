// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 IBM
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

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
    alloc::Layout,
    ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void},
    ptr,
    slice::from_raw_parts,
    str::from_utf8,
};

extern crate alloc;
use alloc::alloc::{alloc, alloc_zeroed, dealloc, realloc as _realloc};
use alloc::boxed::Box;

use super::persistence::CFile;

#[unsafe(no_mangle)]
pub extern "C" fn malloc(size: c_ulong) -> *mut c_void {
    if size == 0 {
        return ptr::null_mut();
    }

    let Ok(layout) = layout_from_size(size as usize) else {
        return ptr::null_mut();
    };

    // SAFETY: layout is guaranteed to be non-zero size. Memory may not be
    // initiatlized, but that's what the caller expects.
    unsafe { alloc(layout).cast() }
}

#[unsafe(no_mangle)]
pub extern "C" fn calloc(items: c_ulong, size: c_ulong) -> *mut c_void {
    let Some(new_size) = items.checked_mul(size) else {
        return ptr::null_mut();
    };

    if new_size == 0 {
        return ptr::null_mut();
    }

    let Ok(layout) = layout_from_size(new_size as usize) else {
        return ptr::null_mut();
    };

    // SAFETY: layout is guaranteed to be non-zero size.
    unsafe { alloc_zeroed(layout).cast() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(p: *mut c_void, size: c_ulong) -> *mut c_void {
    let ptr = p as *mut u8;
    let new_size = size as usize;

    if p.is_null() {
        return malloc(size);
    }

    let Some(layout) = layout_from_ptr(ptr) else {
        return ptr::null_mut();
    };

    if new_size == 0 {
        // SAFETY: layout_from_ptr() call ensures that `ptr` was allocated
        // with this allocator and we are using the same `layout` used to
        // allocate `ptr`.
        unsafe { dealloc(ptr, layout) };
        return ptr::null_mut();
    }

    // This will fail if `new_size` rounded value exceeds `isize::MAX`
    if Layout::from_size_align(new_size, layout.align()).is_err() {
        return ptr::null_mut();
    }

    // SAFETY: layout_from_ptr() call ensures that `ptr` was allocated with
    // this allocator and we are using the same `layout` used to allocate
    // `ptr`. We also checked that `new_size` aligned does not overflow and
    // it is not 0.
    unsafe { _realloc(ptr, layout, new_size).cast() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    let ptr = p as *mut u8;
    let Some(layout) = layout_from_ptr(ptr.cast()) else {
        return;
    };
    // SAFETY: layout_from_ptr() call ensures that `ptr` was allocated
    // with this allocator and we are using the same `layout` used to
    // allocate `ptr`.
    unsafe { dealloc(ptr, layout) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn serial_out(s: *const c_char, size: c_int) {
    // SAFETY: caller must provide safety requirements for
    // [`core::slice::from_raw_parts`]
    let str_slice: &[u8] = unsafe { from_raw_parts(s as *const u8, size as usize) };
    if let Ok(rust_str) = from_utf8(str_slice) {
        _print(format_args!("[SVSM] {rust_str}"));
    } else {
        log::error!("ERR: BUG: serial_out arg1 is not a valid utf8 string");
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn abort() -> ! {
    request_termination_msr();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fopen(path: *const c_char, mode: *const c_char) -> *mut c_void {
    // SAFETY: caller must provide valid null-terminated C strings
    let (path, mode) = unsafe { (CStr::from_ptr(path), CStr::from_ptr(mode)) };
    let (Ok(path), Ok(mode)) = (path.to_str(), mode.to_str()) else {
        return ptr::null_mut();
    };

    match CFile::fopen(path, mode) {
        Some(nv) => Box::into_raw(Box::new(nv)).cast(),
        None => ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fclose(file: *mut c_void) -> c_int {
    if file.is_null() {
        return -1;
    }
    // SAFETY: caller must pass a pointer previously returned by fopen
    let mut nv = unsafe {
        // Reclaim ownership so the CFile is dropped (and its buffer
        // zeroized) when `nv` goes out of scope.
        Box::from_raw(file.cast::<CFile>())
    };
    if nv.save().is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fread(
    buf: *mut c_void,
    size: usize,
    count: usize,
    file: *mut c_void,
) -> usize {
    // SAFETY: caller must pass a pointer previously returned by fopen
    let Some(nv) = (unsafe { file.cast::<CFile>().as_mut() }) else {
        return 0;
    };
    if buf.is_null() || size == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(count) else {
        return 0;
    };
    // SAFETY: buf is non-null (checked above); caller must guarantee
    // it points to at least `size * count` valid bytes
    let dst = unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), total) };
    nv.fread(dst, size).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fwrite(
    buf: *const c_void,
    size: usize,
    count: usize,
    file: *mut c_void,
) -> usize {
    // SAFETY: caller must pass a pointer previously returned by fopen
    let Some(nv) = (unsafe { file.cast::<CFile>().as_mut() }) else {
        return 0;
    };
    if buf.is_null() || size == 0 {
        return 0;
    }
    let Some(total) = size.checked_mul(count) else {
        return 0;
    };
    // SAFETY: buf is non-null (checked above); caller must guarantee
    // it points to at least `size * count` valid bytes
    let src = unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), total) };
    nv.fwrite(src, size).unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fseek(file: *mut c_void, offset: c_long, whence: c_int) -> c_int {
    // SAFETY: caller must pass a pointer previously returned by fopen
    let Some(nv) = (unsafe { file.cast::<CFile>().as_mut() }) else {
        return -1;
    };
    if nv.fseek(offset as isize, whence).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftell(file: *mut c_void) -> c_long {
    // SAFETY: caller must pass a pointer previously returned by fopen
    let Some(nv) = (unsafe { file.cast::<CFile>().as_ref() }) else {
        return -1;
    };
    match nv.ftell() {
        Ok(pos) => pos.try_into().unwrap_or(-1),
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fflush(file: *mut c_void) -> c_int {
    // SAFETY: caller must pass a pointer previously returned by fopen
    let Some(nv) = (unsafe { file.cast::<CFile>().as_mut() }) else {
        return -1;
    };
    if nv.save().is_err() {
        return -1;
    }
    0
}
