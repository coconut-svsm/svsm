// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Thomas Leroy <tleroy@suse.de>

pub mod common;
pub mod svsm;

pub use common::{EARLY_IDT_ENTRIES, IDT, IdtEntry};
pub use svsm::{GLOBAL_IDT, load_static_idt};
