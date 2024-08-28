// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

#![no_std]
#![no_main]

extern crate alloc;
use alloc::ffi::CString;
use buddy_system_allocator::*;
use core::panic::PanicInfo;
use syscall::{exec, exit, SysCallError};

const HEAP_SIZE: usize = 64 * 1024;
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::empty();

#[no_mangle]
pub extern "C" fn init_start() -> ! {
    unsafe {
        HEAP_ALLOCATOR
            .lock()
            .init(core::ptr::addr_of!(HEAP) as usize, HEAP_SIZE);
    }

    let file = CString::new("/dummy").expect("Failed to create new string");
    let root = CString::new("/").expect("Failed to create new string");

    match exec(&file, &root, 0) {
        Ok(_) => exit(0),
        Err(SysCallError::ENOTFOUND) => exit(1),
        _ => panic!("exec launch failed"),
    };
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    exit(u32::MAX);
}
