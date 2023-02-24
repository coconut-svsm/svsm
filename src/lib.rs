// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

#![no_std]
#![feature(const_mut_refs)]

pub mod acpi;
pub mod console;
pub mod cpu;
pub mod fw_cfg;
pub mod fw_meta;
pub mod io;
pub mod kernel_launch;
pub mod locking;
pub mod mm;
pub mod serial;
pub mod sev;
pub mod string;
pub mod svsm_console;
pub mod types;
pub mod utils;
pub mod requests;
pub mod debug;

#[test]
fn test_nop() {}
