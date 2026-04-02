// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use bitfield_struct::bitfield;

use crate::address::{Address, VirtAddr};
use crate::cpu::TlbFlushRange;
use crate::cpu::tlb::TlbFlushScope;
use crate::platform::cpuid;
use crate::types::PageSize;
use crate::utils::MemoryRegion;
use crate::utils::immut_after_init::ImmutAfterInitCell;

use core::arch::asm;

#[bitfield(u64)]
struct InvlpgbRax {
    valid_va: bool,
    valid_pcid: bool,
    valid_asid: bool,
    global: bool,
    final_translation_only: bool,
    nested: bool,
    #[bits(6)]
    _rsvd: u8,
    #[bits(52)]
    va: usize,
}

#[bitfield(u32)]
struct InvlpgbEcx {
    count: u16,
    #[bits(15)]
    _rsvd: u16,
    huge: bool,
}

/// Determines the maximum amount of pages that may be flushed with
/// a single INVLPGB instruction by querying CPUID.
fn __invlpgb_max_count() -> u32 {
    let edx = cpuid(0x80000008, 0).map_or(0, |c| c.edx);
    // EDX[15:0] contains the maximum number of pages that can be
    // invalidated in one instruction. A value of 0 indicates a
    // single page.
    (edx & ((1 << 16) - 1)) + 1
}

/// Determines the maximum amount of pages that may be flushed with
/// a single INVLPGB instruction, by lazily querying CPUID if the
/// value has not been cached from a previous query.
fn invlpgb_max_count() -> u32 {
    static MAX_COUNT: ImmutAfterInitCell<u32> = ImmutAfterInitCell::uninit();
    if let Ok(count) = MAX_COUNT.try_get_inner() {
        return *count;
    }
    let count = __invlpgb_max_count();
    // If this fails, someone else initialized the cell, which is not an issue,
    // as probing CPUID multiple times is benign.
    let _ = MAX_COUNT.init(count);
    count
}

#[inline]
fn do_invlpgb(rax: u64, rcx: u64, rdx: u64) {
    // SAFETY: Inline assembly to invalidate TLB Entries, which does not change
    // any state related to memory safety.
    unsafe {
        asm!("invlpgb",
             in("rax") rax,
             in("rcx") rcx,
             in("rdx") rdx,
             options(att_syntax, nostack, preserves_flags));
    }
}

#[inline]
fn do_tlbsync() {
    // SAFETY: Inline assembly to synchronize TLB invalidations. It does not
    // change any state.
    unsafe {
        asm!("tlbsync", options(att_syntax, nomem, preserves_flags));
    }
}

fn flush_tlb(global: bool) {
    let rax = InvlpgbRax::new().with_valid_asid(true).with_global(global);
    do_invlpgb(rax.into_bits(), 0, 0);
}

fn flush_tlb_sync(global: bool) {
    flush_tlb(global);
    do_tlbsync();
}

fn flush_tlb_sync_range(global: bool, region: MemoryRegion<VirtAddr>, pgsize: PageSize) {
    let max_count = invlpgb_max_count() as usize;

    for start in region.iter_pages(pgsize).step_by(max_count) {
        // Take up to `max_count` pages
        let end = region
            .end()
            .min(start + usize::from(pgsize) * max_count)
            .page_align_up();
        let subregion = MemoryRegion::from_addresses(start, end);
        let page_count = u16::try_from(subregion.len() / usize::from(pgsize)).unwrap();

        let ecx = InvlpgbEcx::new()
            .with_count(page_count)
            .with_huge(pgsize == PageSize::Huge);

        let rax = InvlpgbRax::new()
            .with_valid_asid(true)
            .with_global(global)
            .with_valid_va(true)
            .with_va(start.pfn());

        do_invlpgb(rax.into_bits(), ecx.into_bits() as u64, 0);
    }

    do_tlbsync();
}

fn flush_address(va: VirtAddr) {
    let rax = InvlpgbRax::new()
        .with_valid_asid(true)
        .with_global(true)
        .with_valid_va(true)
        .with_va(va.pfn());
    do_invlpgb(rax.into_bits(), 0, 0);
}

pub fn flush_address_sync(va: VirtAddr) {
    flush_address(va);
    do_tlbsync();
}

pub fn flush_tlb_scope(flush_scope: &TlbFlushScope) {
    match flush_scope.range {
        TlbFlushRange::All => flush_tlb_sync(flush_scope.global),
        TlbFlushRange::Range { region, pgsize } => {
            flush_tlb_sync_range(flush_scope.global, region, pgsize)
        }
    }
}
