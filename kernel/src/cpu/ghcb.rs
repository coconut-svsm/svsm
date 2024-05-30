// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::cpu::percpu::this_cpu;
use crate::sev::ghcb::GHCB;
use core::ops::Deref;

#[derive(Debug)]
pub struct GHCBRef {
    ghcb: *const GHCB,
}

impl Deref for GHCBRef {
    type Target = GHCB;
    fn deref(&self) -> &'static GHCB {
        unsafe { &*self.ghcb }
    }
}

pub fn current_ghcb() -> GHCBRef {
    let ghcb = this_cpu().ghcb_unsafe();
    GHCBRef { ghcb }
}
