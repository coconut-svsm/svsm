// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Peter Fang <peter.fang@intel.com>

#![no_std]
#![no_main]

extern crate alloc;
use alloc::ffi::CString;
use alloc::string::String;
use buddy_system_allocator::*;
use core::ffi::CStr;
use core::panic::PanicInfo;
use syscall::{exec, exit, opendir, readdir, DirEnt, SysCallError, F_TYPE_FILE};

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

    let bin = CString::new("/bin/").expect("Failed to create new string");
    let obj = match opendir(&bin) {
        Ok(obj) => obj,
        _ => exit(0),
    };
    let mut dirents: [DirEnt; 8] = Default::default();
    let mut binfile = CString::default();

    'outer: loop {
        let n = readdir(&obj, &mut dirents).unwrap();
        for d in dirents.iter().take(n) {
            if d.file_type == F_TYPE_FILE {
                binfile = CString::from(CStr::from_bytes_until_nul(&d.file_name).unwrap());
                break 'outer;
            }
        }
        if n < dirents.len() - 1 {
            break;
        }
    }

    if binfile.is_empty() {
        exit(0);
    }

    let mut file = String::from(bin.as_c_str().to_str().unwrap());
    file.push_str(binfile.as_c_str().to_str().unwrap());

    let file = CString::new(file).unwrap();
    let root = CString::new("/").unwrap();

    match exec(&file, &root, 0) {
        Ok(_) => exit(0),
        Err(SysCallError::NotFound) => exit(1),
        _ => panic!("{} launch failed", file.to_str().unwrap()),
    };
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    exit(u32::MAX);
}
