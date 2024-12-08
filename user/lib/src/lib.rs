// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![no_std]

use core::panic::PanicInfo;
pub use syscall::*;

#[macro_export]
macro_rules! declare_main {
    ($path:path) => {
        const _: () = {
            #[export_name = "_start"]
            pub extern "C" fn launch_module() -> ! {
                let main_fn: fn() -> u32 = $path;
                let ret = main_fn();
                exit(ret);
            }
        };
    };
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    exit(!0);
}
