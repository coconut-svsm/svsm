// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::cpu::percpu::this_cpu_unsafe;
use crate::sev::ghcb::GHCB;

use core::ops::Deref;

#[derive(Debug)]
pub struct GHCBRef {
    ghcb: *const GHCB,
}

impl Deref for GHCBRef {
    type Target = GHCB;
    fn deref(&self) -> &GHCB {
        unsafe { &*self.ghcb }
    }
}

pub fn current_ghcb() -> GHCBRef {
    // FIXME - Add borrow checking to GHCB references.
    unsafe {
        let ghcb = (*this_cpu_unsafe()).ghcb_unsafe();
        GHCBRef { ghcb }
    }
}
