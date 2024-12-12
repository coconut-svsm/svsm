// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
use crate::cpu::control_regs::{read_cr3, read_cr4, write_cr3, write_cr4, CR4Flags};
use crate::cpu::ipi::{send_multicast_ipi, IpiMessage, IpiTarget};
use crate::platform::SVSM_PLATFORM;

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

static FLUSH_SMP: AtomicBool = AtomicBool::new(false);

/// Defines the scope of a TLB flush.
#[derive(Copy, Clone, Debug)]
pub enum TlbFlushScope {
    /// Indicates that all addresses must be flushed on all processors,
    /// including global addresses.
    AllGlobal,

    /// Indicates that all addresses must be flushed on all processors,
    /// excluding global addresses.
    AllNonGlobal,
}

impl TlbFlushScope {
    pub fn flush_percpu(&self) {
        match self {
            Self::AllGlobal => flush_tlb_global_percpu(),
            Self::AllNonGlobal => flush_tlb_percpu(),
        }
    }

    pub fn flush_all(&self) {
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
    let flush_scope = TlbFlushScope::AllGlobal;
    flush_scope.flush_all();
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
