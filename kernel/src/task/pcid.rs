// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Tanish Desai
//
// Author: Tanish Desai

use crate::cpu::features::{Feature, cpu_has_feat};
use crate::cpu::tlb::flush_tlb_pcid_sync;
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::alloc::AllocError;
use crate::utils::bitmap_allocator::{BitmapAllocator, BitmapAllocator64, BitmapAllocatorTree};

const PCID_COUNT: usize = 4096;

static PCID_ALLOC: SpinLock<PcidAllocator> = SpinLock::new(PcidAllocator::new());

/// True when PCIDs can be used for task page-table roots.
///
/// Requires `Pcid` (CR4.PCIDE) plus a targeted flush path: INVPCID (`Invpcid`)
/// or AMD INVLPGB (`Invlpgb`).
pub fn pcid_supported() -> bool {
    cpu_has_feat(Feature::Pcid)
        && (cpu_has_feat(Feature::Invpcid) || cpu_has_feat(Feature::Invlpgb))
}

/// Bitmap tracking used PCIDs. Capacity is 64 * 16 * 16 = 16384, which covers
/// the whole `PCID_COUNT` range. Wrapped in an `Option` so the allocator has a
/// `const` initializer (`None`); the bitmap is created on first use via its
/// derived `Default`.
type PcidBitmap = BitmapAllocatorTree<BitmapAllocatorTree<BitmapAllocator64>>;

#[derive(Debug)]
struct PcidAllocator {
    in_use: Option<PcidBitmap>,
}

impl PcidAllocator {
    const fn new() -> Self {
        Self { in_use: None }
    }

    fn alloc(&mut self) -> Result<u16, SvsmError> {
        let in_use = self.in_use.get_or_insert_with(PcidBitmap::default);
        // PCID 0 is reserved as the "overflow" PCID, so allocation starts at
        // index 1 and is bounded to the architectural PCID range.
        let idx = in_use
            .next_free(1)
            .filter(|&idx| idx < PCID_COUNT)
            .ok_or(SvsmError::Alloc(AllocError::OutOfMemory))?;
        in_use.set(idx, 1, true);
        Ok(idx as u16)
    }

    fn release(&mut self, pcid: u16) {
        flush_tlb_pcid_sync(pcid);
        let in_use = self.in_use.get_or_insert_with(PcidBitmap::default);
        in_use.free(usize::from(pcid), 1);
    }
}

/// Owned PCID for a task page-table root.
#[derive(Debug)]
pub struct TaskPcid {
    pcid: u16,
}

impl TaskPcid {
    pub fn new() -> Result<Self, SvsmError> {
        let pcid = PCID_ALLOC.lock().alloc()?;
        Ok(Self { pcid })
    }

    pub fn pcid(&self) -> u16 {
        self.pcid
    }
}

impl Drop for TaskPcid {
    fn drop(&mut self) {
        PCID_ALLOC.lock().release(self.pcid);
    }
}
