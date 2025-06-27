// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Thomas Leroy <tleroy@suse.de>

pub mod common;
pub mod stage2;
pub mod svsm;

pub use common::{IdtEntry, EARLY_IDT_ENTRIES, IDT};
pub use svsm::{load_static_idt, GLOBAL_IDT};
