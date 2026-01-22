// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Thomas Leroy <tleroy@suse.de>

pub mod apic;
pub mod smap;
pub mod x2apic;

pub use apic::{
    ApicAccess, MSR_APIC_BASE, X86Apic, apic_enable, apic_eoi, apic_in_service, apic_initialize,
    apic_post_irq, apic_sw_enable,
};
pub use x2apic::{X2APIC_ACCESSOR, X2ApicAccessor};
