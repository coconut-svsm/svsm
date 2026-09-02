// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Tanish Desai
//
// Author: Tanish Desai

use crate::cpu::features::{Feature, cpu_has_feat};
use crate::cpu::tlb::flush_tlb_pcid_sync;
use crate::error::SvsmError;
use crate::flat_bitmap_allocator;
use crate::mm::alloc::AllocError;

const PCID_COUNT: usize = 4096;

/// Bitmap of allocated PCIDs. PCID 0 is reserved as the overflow PCID and is
/// claimed on first allocation (see [`alloc_pcid`]).
static PCID_ALLOC: flat_bitmap_allocator!(PCID_COUNT) = <flat_bitmap_allocator!(PCID_COUNT)>::new();

/// True when PCIDs can be used for task page-table roots.
///
/// Requires `Pcid` (CR4.PCIDE) and `Invpcid`. AMD Zen 3+ added PCID and
/// INVPCID together; INVLPGB is a broadcast optimization, not a substitute
/// for INVPCID.
pub fn pcid_supported() -> bool {
    cpu_has_feat(Feature::Pcid) && cpu_has_feat(Feature::Invpcid)
}

fn alloc_pcid() -> Result<u16, SvsmError> {
    loop {
        let idx = PCID_ALLOC
            .alloc()
            .ok_or(SvsmError::Alloc(AllocError::OutOfMemory))?;
        // PCID 0 is reserved; leave it allocated and take the next free id.
        if idx != 0 {
            return Ok(idx as u16);
        }
    }
}

fn release_pcid(pcid: u16) {
    flush_tlb_pcid_sync(pcid);
    PCID_ALLOC.free(usize::from(pcid));
}

/// Owned PCID for a task page-table root.
#[derive(Debug)]
pub struct TaskPcid {
    pcid: u16,
}

impl TaskPcid {
    pub fn new() -> Result<Self, SvsmError> {
        Ok(Self {
            pcid: alloc_pcid()?,
        })
    }

    pub fn pcid(&self) -> u16 {
        self.pcid
    }
}

impl Drop for TaskPcid {
    fn drop(&mut self) {
        release_pcid(self.pcid);
    }
}
