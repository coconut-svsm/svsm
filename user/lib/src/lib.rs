// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![cfg_attr(all(not(test), target_os = "none"), no_std)]

pub mod console;
pub mod locking;
pub mod log_buffer;

pub use console::*;
pub use locking::*;
pub use log_buffer::*;
pub use syscall::*;

pub use log;

#[cfg(all(feature = "test_runner", not(test), target_os = "none"))]
pub mod testing;
#[cfg(all(feature = "test_runner", not(test), target_os = "none"))]
pub use testing::*;

#[macro_export]
macro_rules! declare_main {
    ($path:path) => {
        const _: () = {
            #[unsafe(export_name = "_start")]
            pub extern "C" fn launch_module() -> ! {
                $crate::install_logger();
                let main_fn: fn() -> u32 = $path;
                let ret = main_fn();
                $crate::exit(ret);
            }
        };
    };
}

#[cfg(all(not(test), target_os = "none"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    log::error!("Panic: {}", info);
    exit(!0);
}
