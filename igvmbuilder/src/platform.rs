// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use std::sync::atomic::{AtomicU32, Ordering};

pub struct PlatformMask {
    mask: AtomicU32,
}

impl PlatformMask {
    pub const fn new() -> Self {
        Self {
            mask: AtomicU32::new(0),
        }
    }

    pub fn get(&self) -> u32 {
        self.mask.load(Ordering::Relaxed)
    }

    pub fn add(&self, add_mask: u32) {
        self.mask.fetch_or(add_mask, Ordering::Relaxed);
    }

    pub fn contains(&self, test_mask: u32) -> bool {
        (self.mask.load(Ordering::Relaxed) & test_mask) != 0
    }
}
