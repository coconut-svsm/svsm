// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Tanish Desai
//
// Author: Tanish Desai

//! Shared set of PCIDs that may cache translations for a VMR.
//!
//! Threads can share VMRs while each having its own page-table root and PCID.
//! Unmaps through those VMRs must shoot down every PCID that could still hold
//! the old translations.

use crate::address::VirtAddr;
use crate::cpu::{flush_tlb_global_sync_range, flush_tlb_pcid_sync_range};
use crate::locking::SpinLock;
use crate::types::PageSize;
use crate::utils::MemoryRegion;
use core::sync::atomic::{AtomicUsize, Ordering};

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// PCIDs of page-table roots that may contain translations for a shared VMR.
#[derive(Debug, Default)]
pub struct PcidSet {
    /// Allocated PCIDs (unique per page-table root).
    ids: SpinLock<Vec<u16>>,
    /// Tasks that fell back to reserved PCID 0 when the pool was exhausted.
    overflow: AtomicUsize,
}

impl PcidSet {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn insert(&self, pcid: u16) {
        if pcid == 0 {
            self.overflow.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut ids = self.ids.lock();
        if !ids.contains(&pcid) {
            ids.push(pcid);
        }
    }

    pub fn remove(&self, pcid: u16) {
        if pcid == 0 {
            // Underflow means an unmatched remove; ignore it.
            loop {
                let n = self.overflow.load(Ordering::Relaxed);
                if n == 0 {
                    return;
                }
                if self
                    .overflow
                    .compare_exchange_weak(n, n - 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
            }
        }
        self.ids.lock().retain(|&id| id != pcid);
    }

    /// Invalidate `region` for every registered PCID, or globally if none.
    pub fn flush_range(&self, region: MemoryRegion<VirtAddr>, pgsize: PageSize) {
        let ids = self.ids.lock().clone();
        let overflow = self.overflow.load(Ordering::Relaxed);
        if ids.is_empty() && overflow == 0 {
            flush_tlb_global_sync_range(region, pgsize);
            return;
        }
        for pcid in ids {
            flush_tlb_pcid_sync_range(pcid, region, pgsize);
        }
        if overflow > 0 {
            flush_tlb_pcid_sync_range(0, region, pgsize);
        }
    }
}
