// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
#![no_std]

mod call;
mod class0;
mod class1;
mod console;
mod def;
mod obj;

pub use call::SysCallError;
pub use class0::*;
pub use class1::*;
pub use console::*;
pub use def::*;
pub use obj::*;
