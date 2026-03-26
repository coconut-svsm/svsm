// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use bitfield_struct::bitfield;

use crate::address::{Address, VirtAddr};
use crate::cpu::tlb::TlbFlushScope;

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

#[inline]
fn do_invlpgb(rax: u64, rcx: u64, rdx: u64) {
    // SAFETY: Inline assembly to invalidate TLB Entries, which does not change
    // any state related to memory safety.
    unsafe {
        asm!("invlpgb",
             in("rax") rax,
             in("rcx") rcx,
             in("rdx") rdx,
             options(att_syntax));
    }
}

#[inline]
fn do_tlbsync() {
    // SAFETY: Inline assembly to synchronize TLB invalidations. It does not
    // change any state.
    unsafe {
        asm!("tlbsync", options(att_syntax));
    }
}

pub fn flush_tlb(global: bool) {
    let rax = InvlpgbRax::new().with_valid_asid(true).with_global(global);
    do_invlpgb(rax.into_bits(), 0, 0);
}

pub fn flush_tlb_sync(global: bool) {
    flush_tlb(global);
    do_tlbsync();
}

pub fn flush_address(va: VirtAddr) {
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
    flush_tlb_sync(flush_scope.global);
}
