// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Thomas Leroy <tleroy@suse.de>

pub mod apic;
pub mod smap;
pub mod x2apic;

pub use apic::{
    apic_enable, apic_eoi, apic_in_service, apic_initialize, apic_post_irq, apic_sw_enable,
    ApicAccess, X86Apic, MSR_APIC_BASE,
};
pub use x2apic::{X2ApicAccessor, X2APIC_ACCESSOR};
