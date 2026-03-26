// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
use crate::cpu::control_regs::{CR4Flags, read_cr3, read_cr4, write_cr3, write_cr4};
use crate::cpu::ipi::{IpiMessage, IpiTarget, send_multicast_ipi};
use crate::platform::SVSM_PLATFORM;
use crate::types::PageSize;
use crate::utils::MemoryRegion;

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

static FLUSH_SMP: AtomicBool = AtomicBool::new(false);

/// When a partial TLB flush is requested, if the amount of PTEs that
/// need to be flushed exceeds this value, a complete TLB flush will
/// be performed instead.
const TLB_FLUSH_ALL_THRESHOLD: usize = 256;

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
}

impl TlbFlushScope {
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
        match self.global {
            true => flush_tlb_global_percpu(),
            false => flush_tlb_percpu(),
        }
    }

    /// Flushes the TLB for all CPUs.
    pub fn flush_smp(&self) {
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

pub fn flush_tlb_global_sync() {
    let flush_scope = TlbFlushScope {
        global: true,
        range: TlbFlushRange::All,
    };
    flush_scope.flush_smp();
}

pub fn flush_tlb_global_percpu() {
    let cr4 = read_cr4();

    // SAFETY: we are not changing any execution-state relevant flags
    unsafe {
        write_cr4(cr4 ^ CR4Flags::PGE);
        write_cr4(cr4);
    }
}

pub fn flush_tlb_percpu() {
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
