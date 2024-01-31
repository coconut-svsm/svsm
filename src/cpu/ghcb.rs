// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::cpu::percpu::this_cpu_unsafe;
use crate::sev::ghcb::GHCB;

use core::ops::{Deref, DerefMut};

#[derive(Debug)]
pub struct GHCBRef {
    ghcb: *mut GHCB,
}

impl Deref for GHCBRef {
    type Target = GHCB;
    fn deref(&self) -> &'static GHCB {
        unsafe { &*self.ghcb }
    }
}

impl DerefMut for GHCBRef {
    fn deref_mut(&mut self) -> &'static mut GHCB {
        unsafe { &mut *self.ghcb }
    }
}

pub fn current_ghcb() -> GHCBRef {
    // FIXME - Add borrow checking to GHCB references.
    unsafe {
        let cpu_ptr = this_cpu_unsafe();
        let cpu = &mut *cpu_ptr;
        let ghcb = cpu.ghcb_unsafe();
        GHCBRef { ghcb }
    }
}
