// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>

//! TLB invalidation hooks and the [`MayNeedFlush`] obligation token.

use crate::address::VirtAddr;
use crate::traits::PageLevel;

/// Architecture/OS hooks for TLB invalidation, plus the small algebra used to
/// combine pending invalidations.
///
/// A value implementing `TlbFlush` is an opaque *flush token*: it describes
/// which TLB entries a page-table mutation may have made stale. The `paging`
/// crate never flushes directly; it hands these tokens back inside a
/// [`MayNeedFlush`] and lets the OS decide how and when to discharge them.
///
/// This is referenced by [`ArchPagingMeta`](crate::traits::ArchPagingMeta) via
/// its [`TlbFlushTok`](crate::traits::ArchPagingMeta::TlbFlushTok) associated
/// type, keeping TLB concerns separate from address-encoding concerns. The
/// discharge method names mirror the kernel's `cpu::tlb` free functions.
pub trait TlbFlush: Sized {
    /// Build a token covering the half-open virtual range `[start, end)` whose
    /// mapping was changed at `page_size`.
    fn range(start: VirtAddr, end: VirtAddr, page_size: PageLevel) -> Self;

    /// Build a token that stands for "flush the entire TLB".
    ///
    /// Used when a mutation's precise footprint is unknown or when merging two
    /// disjoint tokens (see [`and`](Self::and)).
    fn all() -> Self;

    /// Flush the TLB on all CPUs, including global pages.
    fn flush_tlb_global_sync(self);

    /// Merge two tokens into one that covers both.
    ///
    /// The default implementation is conservative: it widens to
    /// [`all`](Self::all) rather than tracking a union of ranges. Override it
    /// to preserve range precision when the architecture can flush selectively.
    fn and(self, _: Self) -> Self {
        Self::all()
    }

    /// Flush the TLB on the current CPU only, including global pages.
    ///
    /// The default implementation falls back to the cross-CPU
    /// [`flush_tlb_global_sync`](Self::flush_tlb_global_sync); override it for a
    /// cheaper CPU-local flush.
    fn flush_tlb_global_percpu(self) {
        self.flush_tlb_global_sync()
    }

    /// Flush the TLB on all CPUs, ignoring global pages.
    ///
    /// The default implementation is conservative and falls back to
    /// [`flush_tlb_global_sync`](Self::flush_tlb_global_sync), which also
    /// flushes global pages; override it to avoid that extra work.
    fn flush_tlb_ignore_global_sync(self) {
        self.flush_tlb_global_sync()
    }

    /// Flush the TLB on the current CPU only, ignoring global pages.
    ///
    /// The default implementation is conservative and falls back to
    /// [`flush_tlb_global_percpu`](Self::flush_tlb_global_percpu), which also
    /// flushes global pages; override it to avoid that extra work.
    fn flush_tlb_ignore_global_percpu(self) {
        self.flush_tlb_global_percpu()
    }
}

/// A `#[must_use]` marker meaning the caller *may* still owe a TLB
/// invalidation for the mapping it just modified.
///
/// `#[must_use]` is **not** a hard check. It does not guarantee a flush ever
/// happens and it is trivially silenced; it is purely a quick hint that nudges
/// the developer to handle the obligation at the call site. Treat it as a lint,
/// not as a verified safety property.
///
/// The wrapped `tok` is `None` when no flush is needed and `Some(token)`
/// otherwise. The token also records *what* to flush: a mutation to a 4 KiB
/// page may require flushing the enclosing larger page. For example, changing
/// the encryption flags of a 4 KiB page that was carved out of a 2 MiB huge
/// page can require flushing the 2 MiB translation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "this page-table mutation may have invalidated a live TLB entry; \
flush the affected page or discharge the obligation with `.ignore(reason)`"]
pub struct MayNeedFlush<T: TlbFlush> {
    tok: Option<T>,
}

impl<A: TlbFlush> MayNeedFlush<A> {
    pub fn scope(&self) -> &Option<A> {
        &self.tok
    }
    /// Creates an obligation to flush the single page at `vaddr` mapped at
    /// `level`.
    ///
    /// Most callers get their token back from a `paging`-crate mutation helper
    /// (e.g. `unmap_4k`, `set_shared_4k`) that already captured the level a
    /// walk stopped at, rather than constructing one directly.
    pub fn new(vaddr: VirtAddr, level: PageLevel) -> Self {
        MayNeedFlush {
            tok: Some(A::range(vaddr, vaddr + level.size(), level)),
        }
    }

    /// Creates an obligation to flush the half-open range `[start, end)`,
    /// where each entry was mapped at `level`.
    ///
    /// Use this only when a caller outside of `paging` performs its own
    /// low-level page-table edit (e.g. looping over a region and writing
    /// entries directly) and must therefore vouch for the range and level
    /// itself.
    pub fn new_range(start: VirtAddr, end: VirtAddr, level: PageLevel) -> Self {
        MayNeedFlush {
            tok: Some(A::range(start, end, level)),
        }
    }

    /// Creates a discharged token: the mutation needs no flush.
    ///
    /// Returned by helpers that observed no change to a live translation (e.g.
    /// writing a previously-empty entry).
    pub fn none() -> Self {
        MayNeedFlush { tok: None }
    }

    /// Creates an obligation to flush the whole TLB.
    ///
    /// Use when a flush is required but its precise footprint is unknown.
    pub fn all() -> Self {
        MayNeedFlush {
            tok: Some(A::all()),
        }
    }

    /// Combines two obligations into one covering both.
    ///
    /// The result is discharged only if both inputs are; a pending token on
    /// either side is preserved, and two pending tokens are merged via
    /// [`TlbFlush::and`].
    pub fn and(self, other: Self) -> Self {
        match (self.tok, other.tok) {
            (Some(tok1), Some(tok2)) => MayNeedFlush {
                tok: Some(A::and(tok1, tok2)),
            },
            (Some(tok), None) | (None, Some(tok)) => MayNeedFlush { tok: Some(tok) },
            (None, None) => MayNeedFlush { tok: None },
        }
    }

    /// Discharge by flushing the TLB on all CPUs, ignoring global pages.
    ///
    /// Dispatches to [`TlbFlush::flush_tlb_ignore_global_sync`].
    ///
    /// # Panics
    ///
    /// Panics if the obligation is already discharged (`tok` is `None`); call
    /// only when a flush is actually pending.
    pub fn flush_tlb_ignore_global_sync(self) {
        self.tok.unwrap().flush_tlb_ignore_global_sync();
    }

    /// Discharge by flushing the whole TLB (including global pages) on all
    /// CPUs (the coarsest option).
    ///
    /// Dispatches to [`TlbFlush::flush_tlb_global_sync`].
    ///
    /// # Panics
    ///
    /// Panics if the obligation is already discharged (`tok` is `None`).
    pub fn flush_tlb_global_sync(self) {
        self.tok.unwrap().flush_tlb_global_sync();
    }

    /// Discharge by flushing the whole TLB (including global pages) on the
    /// **current CPU only**, without a cross-CPU IPI.
    ///
    /// Dispatches to [`TlbFlush::flush_tlb_global_percpu`]. Use only when the
    /// changed mapping cannot be live on any other CPU.
    ///
    /// # Panics
    ///
    /// Panics if the obligation is already discharged (`tok` is `None`).
    pub fn flush_tlb_global_percpu(self) {
        self.tok.unwrap().flush_tlb_global_percpu();
    }

    /// Discharge by flushing the non-global TLB entries on the **current CPU
    /// only**.
    ///
    /// Dispatches to [`TlbFlush::flush_tlb_ignore_global_percpu`].
    ///
    /// # Panics
    ///
    /// Panics if the obligation is already discharged (`tok` is `None`).
    pub fn flush_tlb_percpu(self) {
        self.tok.unwrap().flush_tlb_ignore_global_percpu();
    }

    /// Discharge the flush obligation **without** flushing.
    /// This method is `unsafe` because it allows the caller to bypass the TLB flush
    /// obligation.
    ///
    /// # Safety
    /// The caller must ensure TLB flush is not needed.
    pub unsafe fn ignore(self) {}

    /// Assert that no flush is owed, consuming the obligation.
    ///
    /// # Panics
    ///
    /// Panics if a flush is still pending (`tok` is `Some`). Use at call sites
    /// that must never produce a stale translation.
    pub fn expect_no_flush(self) {
        assert!(self.tok.is_none());
    }
}
