// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![no_std]
#![no_main]

use core::ffi::CStr;
use userlib::*;

declare_main!(main);
fn main() -> u32 {
    println!("COCONUT-SVSM init process starting");

    let obj = opendir(c"/").expect("Cannot open root directory");

    // Discover the first file under root directory, excluding `/init`.
    let mut dirents: [DirEnt; 8] = Default::default();
    let binfile = loop {
        let n = readdir(&obj, &mut dirents).unwrap();
        if let Some(f) = dirents
            .iter()
            .take(n)
            .filter(|d| d.file_type == FileType::File)
            .map(|d| {
                CStr::from_bytes_until_nul(&d.file_name).expect("Filename is not nul-terminated!")
            })
            .find(|&f| f != c"init")
        {
            break f;
        }
        if n < dirents.len() {
            return 0;
        }
    };

    let mut path = [b'\0'; F_NAME_SIZE + 1];
    path[0] = b'/';
    path[1..=binfile.count_bytes()].copy_from_slice(binfile.to_bytes());
    let file = CStr::from_bytes_until_nul(&path).unwrap();

    match exec(file, c"/", 0) {
        Ok(_) => 0,
        Err(SysCallError::ENOTFOUND) => 1,
        _ => panic!("{} launch failed", file.to_str().unwrap()),
    }
}
