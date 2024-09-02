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
use syscall::{exec, exit, opendir, readdir, DirEnt, FileType, SysCallError};

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

    let bin = CString::new("/bin/").unwrap();
    let Ok(obj) = opendir(&bin) else {
        exit(0);
    };
    let mut dirents: [DirEnt; 8] = Default::default();
    let mut binfile: Option<CString> = None;

    loop {
        let n = readdir(&obj, &mut dirents).unwrap();
        if let Some(d) = dirents
            .iter()
            .take(n)
            .find(|d| d.file_type == FileType::File)
        {
            binfile = Some(CString::from(
                CStr::from_bytes_until_nul(&d.file_name).unwrap(),
            ));
            break;
        }
        if n < dirents.len() {
            break;
        }
    }
    let binfile = binfile.unwrap_or_else(|| exit(0));

    let mut file = String::from(bin.as_c_str().to_str().unwrap());
    file.push_str(binfile.as_c_str().to_str().unwrap());

    let file = CString::new(file).unwrap();
    let root = CString::new("/").unwrap();

    match exec(&file, &root, 0) {
        Ok(_) => exit(0),
        Err(SysCallError::ENOTFOUND) => exit(1),
        _ => panic!("{} launch failed", file.to_str().unwrap()),
    };
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    exit(u32::MAX);
}
