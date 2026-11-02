// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
#![no_std]

mod call;
mod class0;
mod class1;
mod class3;
mod def;
mod logging;
mod obj;
mod sysno;

pub use call::{SysCallError, syscall0, syscall1, syscall2, syscall3, syscall4, syscall5};
pub use class0::*;
pub use class1::*;
pub use class3::*;
pub use def::*;
pub use logging::*;
pub use obj::*;
pub use sysno::*;
