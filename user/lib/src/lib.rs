// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![cfg_attr(all(not(test), target_os = "none"), no_std)]

pub mod alloc;
pub mod console;
pub mod locking;
pub use alloc::*;
pub use console::*;
pub use locking::*;
pub use syscall::*;

#[macro_export]
macro_rules! declare_main {
    ($path:path) => {
        const _: () = {
            #[unsafe(export_name = "_start")]
            pub extern "C" fn launch_module() -> ! {
                init();

                let main_fn: fn() -> u32 = $path;
                let ret = main_fn();
                exit(ret);
            }
        };
    };
}

pub fn init() {
    #[cfg(all(not(test), target_os = "none"))]
    {
        // Single-threaded init process, safe to initialize global heap here
        set_global_heap().expect("Heap initialization failed");
    }
}

#[cfg(all(not(test), target_os = "none"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("Panic: {}", info);
    exit(!0);
}
