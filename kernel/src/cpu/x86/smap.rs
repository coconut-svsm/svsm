// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Thomas Leroy <tleroy@suse.de>

use core::arch::asm;

/// Clears RFLAGS.AC to enable SMAP.
/// This is currently only used when SMAP is supported and enabled.
/// SMAP protection is effective only if CR4.SMAP is set and if RFLAGS.AC = 0.
#[inline(always)]
pub fn clac() {
    if !cfg!(feature = "nosmap") {
        // SAFETY: `clac` instruction doesn't break memory safety.
        unsafe { asm!("clac", options(att_syntax, nomem, nostack, preserves_flags)) }
    }
}

/// Sets RFLAGS.AC to disable SMAP.
/// This is currently only used when SMAP is supported and enabled.
/// SMAP protection is effective only if CR4.SMAP is set and if RFLAGS.AC = 0.
#[inline(always)]
pub fn stac() {
    if !cfg!(feature = "nosmap") {
        // SAFETY: `stac` instruction doesn't break memory safety.
        unsafe { asm!("stac", options(att_syntax, nomem, nostack, preserves_flags)) }
    }
}
