// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![cfg_attr(all(not(test), target_os = "none"), no_std)]

pub mod console;
pub mod locking;

pub use console::*;
pub use locking::*;
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

#[cfg(all(not(test), target_os = "none"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("Panic: {}", info);
    exit(!0);
}
