// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
#![no_std]

mod call;
mod numbers;
mod obj;

pub use call::SysCallError;
pub use numbers::*;
pub use obj::*;
