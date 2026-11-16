// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) Coconut-SVSM authors

use core::sync::atomic::{AtomicBool, Ordering};

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Marks the beginning of panic handling and returns whether this is the first
/// panic in the guest.
pub fn enter() -> bool {
    !ACTIVE.swap(true, Ordering::Relaxed)
}

/// Returns whether panic handling is in progress.
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}
