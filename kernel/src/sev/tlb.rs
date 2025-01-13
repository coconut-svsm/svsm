// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
use crate::cpu::tlb::TlbFlushScope;

use core::arch::asm;

const INVLPGB_VALID_VA: u64 = 1u64 << 0;
//const INVLPGB_VALID_PCID: u64 = 1u64 << 1;
const INVLPGB_VALID_ASID: u64 = 1u64 << 2;
const INVLPGB_VALID_GLOBAL: u64 = 1u64 << 3;

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

pub fn flush_tlb() {
    let rax: u64 = INVLPGB_VALID_ASID;
    do_invlpgb(rax, 0, 0);
}

pub fn flush_tlb_sync() {
    flush_tlb();
    do_tlbsync();
}

pub fn flush_tlb_global() {
    let rax: u64 = INVLPGB_VALID_ASID | INVLPGB_VALID_GLOBAL;
    do_invlpgb(rax, 0, 0);
}

pub fn flush_tlb_global_sync() {
    flush_tlb_global();
    do_tlbsync();
}

pub fn flush_address(va: VirtAddr) {
    let rax: u64 = (va.page_align().bits() as u64)
        | INVLPGB_VALID_VA
        | INVLPGB_VALID_ASID
        | INVLPGB_VALID_GLOBAL;
    do_invlpgb(rax, 0, 0);
}

pub fn flush_address_sync(va: VirtAddr) {
    flush_address(va);
    do_tlbsync();
}

pub fn flush_tlb_scope(flush_scope: &TlbFlushScope) {
    match flush_scope {
        TlbFlushScope::AllGlobal => flush_tlb_global_sync(),
        TlbFlushScope::AllNonGlobal => flush_tlb_sync(),
    }
}
