// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Thomas Leroy <tleroy@suse.de>

pub mod apic;
pub mod smap;
pub mod x2apic;

pub use apic::{ApicAccess, X86Apic, MSR_APIC_BASE};
pub use x2apic::{X2ApicAccessor, X2APIC_ACCESSOR};
