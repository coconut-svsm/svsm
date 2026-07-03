// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
use crate::cpu::control_regs::{read_cr3, read_cr4, write_cr3, write_cr4};
use crate::cpu::features::{Feature, cpu_has_feat};
use crate::cpu::ipi::{IpiMessage, IpiTarget, send_multicast_ipi};
use crate::platform::SVSM_PLATFORM;
use crate::types::PageSize;
use crate::utils::MemoryRegion;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};
use cpuarch::x86::CR4Flags;

static FLUSH_SMP: AtomicBool = AtomicBool::new(false);

/// When a partial TLB flush is requested, if the amount of PTEs that
/// need to be flushed exceeds this value, a complete TLB flush will
/// be performed instead.
const TLB_FLUSH_ALL_THRESHOLD: usize = 256;

/// INVPCID descriptor (Intel SDM Vol. 2A, `INVPCID`).
#[repr(C, align(16))]
struct InvpcidDesc {
    pcid: u64,
    reserved: u64,
}

/// Defines the scope of a TLB flush.
#[derive(Copy, Clone, Debug)]
pub enum TlbFlushRange {
    All,
    Range {
        /// The range of addresses to be flush.
        region: MemoryRegion<VirtAddr>,
        /// The size of the PTEs used to map the region being flushed.
        pgsize: PageSize,
    },
}

/// Defines the scope of a TLB flush.
#[derive(Copy, Clone, Debug)]
pub struct TlbFlushScope {
    /// Indicates whether global addresses should be flushed or not.
    pub global: bool,
    /// Indicates the range of virtual addresses that should be flushed.
    pub range: TlbFlushRange,
    /// When set, flush all non-global entries for this PCID (INVPCID or
    /// INVLPGB, depending on CPU features).
    pub pcid: Option<u16>,
}

impl TlbFlushScope {
    /// Creates a TLB flush scope for all all addresses (including global).
    pub const fn all() -> Self {
        Self {
            global: true,
            range: TlbFlushRange::All,
            pcid: None,
        }
    }

    /// Creates a TLB flush scope targeting all non-global entries tagged with the given PCID.
    pub const fn pcid(pcid: u16) -> Self {
        Self {
            global: false,
            range: TlbFlushRange::All,
            pcid: Some(pcid),
        }
    }

    /// Updates the scope to include or exclude global pages, as indicated.
    pub const fn with_global(mut self, global: bool) -> Self {
        self.global = global;
        self
    }

    /// Creates a new TLB flush scope, including only a range of virtual addresses
    /// (which may be global).
    pub const fn range(region: MemoryRegion<VirtAddr>, pgsize: PageSize) -> Self {
        Self {
            global: true,
            range: TlbFlushRange::Range { region, pgsize },
            pcid: None,
        }
    }

    /// Creates a new TLB flush scope, including only a single page (which may be
    /// global).
    pub fn page(va: VirtAddr, pgsize: PageSize) -> Self {
        let region = MemoryRegion::new(va, usize::from(pgsize));
        Self::range(region, pgsize)
    }

    /// Flushes the TLB for the current CPU.
    pub fn flush_percpu(&self) {
        match self.range {
            TlbFlushRange::All => self.flush_percpu_all(),
            TlbFlushRange::Range { region, pgsize } => {
                let page_count = region.len().div_ceil(usize::from(pgsize));
                // Perform a complete flush if the number of PTEs exceeds the
                // threshold.
                if page_count > TLB_FLUSH_ALL_THRESHOLD {
                    self.flush_percpu_all();
                } else {
                    for page in region.iter_pages(pgsize) {
                        flush_address_percpu(page);
                    }
                }
            }
        }
    }

    /// Flushes all the entries in the TLB for the current CPU.
    fn flush_percpu_all(&self) {
        if let Some(pcid) = self.pcid {
            flush_pcid_percpu(pcid);
            return;
        }
        match self.global {
            true => __flush_tlb_global_percpu(),
            false => __flush_tlb_percpu(),
        }
    }

    /// Flushes the TLB for all CPUs.
    pub fn flush_all_cpus(&self) {
        // If SMP has not yet been started, then perform all flushes as local only.
        // Prior to SMP startup, there is no need to reach into other processors,
        // and the SVSM platform object may not even exist when flushes are
        // attempted prior to SMP startup.
        if FLUSH_SMP.load(Ordering::Relaxed) {
            SVSM_PLATFORM.flush_tlb(self);
        } else {
            self.flush_percpu();
        }
    }
}

// SAFETY: The TlbFlushScope structure contains no references and can safely
// rely on the default implementation of the IPI message copy routines.
unsafe impl IpiMessage for TlbFlushScope {
    fn invoke(&self) {
        self.flush_percpu();
    }
}

pub fn flush_tlb(flush_scope: &TlbFlushScope) {
    send_multicast_ipi(IpiTarget::All, flush_scope);
}

pub fn set_tlb_flush_smp() {
    FLUSH_SMP.store(true, Ordering::Relaxed);
}

/// Flushes all non-global TLB entries tagged with `pcid` on all CPUs.
pub fn flush_tlb_pcid_sync(pcid: u16) {
    TlbFlushScope::pcid(pcid).flush_all_cpus();
}

pub fn flush_tlb_global_sync() {
    TlbFlushScope::all().with_global(true).flush_all_cpus();
}

pub fn flush_tlb_global_sync_range(region: MemoryRegion<VirtAddr>, pgsize: PageSize) {
    TlbFlushScope::range(region, pgsize)
        .with_global(true)
        .flush_all_cpus();
}

pub fn flush_tlb_global_sync_page(vaddr: VirtAddr, pgsize: PageSize) {
    TlbFlushScope::page(vaddr, pgsize)
        .with_global(true)
        .flush_all_cpus();
}

pub fn flush_tlb_global_percpu() {
    TlbFlushScope::all().with_global(true).flush_percpu();
}

pub fn flush_tlb_global_percpu_range(region: MemoryRegion<VirtAddr>, pgsize: PageSize) {
    TlbFlushScope::range(region, pgsize)
        .with_global(true)
        .flush_percpu();
}

pub fn flush_tlb_global_percpu_page(vaddr: VirtAddr, pgsize: PageSize) {
    TlbFlushScope::page(vaddr, pgsize)
        .with_global(true)
        .flush_percpu();
}

pub fn flush_tlb_percpu() {
    TlbFlushScope::all().with_global(false).flush_percpu();
}

fn flush_pcid_percpu(pcid: u16) {
    if cpu_has_feat(Feature::Invpcid) {
        let desc = InvpcidDesc {
            pcid: u64::from(pcid),
            reserved: 0,
        };
        // SAFETY: INVPCID type 1 (single-context invalidation) flushes all
        // non-global TLB entries for the PCID in desc. Type in any GPR,
        // descriptor in memory. The descriptor must be 16-byte aligned;
        // alignment is guaranteed by InvpcidDesc's #[repr(C, align(16))] attribute.
        unsafe {
            asm!("invpcid ({0}), {1}",
                 in(reg) &raw const desc,
                 in(reg) 1u64,
                 options(att_syntax));
        }
    }
}

fn __flush_tlb_global_percpu() {
    let cr4 = read_cr4();

    // SAFETY: we are not changing any execution-state relevant flags
    unsafe {
        write_cr4(cr4 ^ CR4Flags::PGE);
        write_cr4(cr4);
    }
}

fn __flush_tlb_percpu() {
    // SAFETY: reloading CR3 with its current value is always safe.
    unsafe {
        write_cr3(read_cr3());
    }
}

pub fn flush_address_percpu(va: VirtAddr) {
    let va: u64 = va.page_align().bits() as u64;
    // SAFETY: Inline assembly to invalidate TLB Entries, which does not change
    // any state related to memory safety.
    unsafe {
        asm!("invlpg (%rax)",
             in("rax") va,
             options(att_syntax));
    }
}
