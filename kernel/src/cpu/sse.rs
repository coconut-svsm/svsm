// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

use crate::cpu::control_regs::{cr0_sse_enable, cr4_osfxsr_enable, cr4_xsave_enable};
use core::arch::asm;
use core::arch::x86_64::{_xgetbv, _xsetbv};
use core::sync::atomic::{AtomicU64, Ordering};

use super::features::{Feature, cpu_has_feat};

const XCR0_X87_ENABLE: u64 = 0x1;
const XCR0_SSE_ENABLE: u64 = 0x2;
const XCR0_YMM_ENABLE: u64 = 0x4;

static SVSM_XCR0: AtomicU64 = AtomicU64::new(XCR0_X87_ENABLE | XCR0_SSE_ENABLE);

fn legacy_sse_enable() {
    if cpu_has_feat(Feature::Sse1) {
        cr4_osfxsr_enable();
        cr0_sse_enable();
    } else {
        panic!("Legacy SSE unsupported");
    }
}

fn xcr0_set() {
    // SAFETY: No impact on memory safety, enables FPU87 and SSE XSAVE features
    unsafe {
        // set bits [0-2] in XCR0 to enable extended SSE
        let xr0 = _xgetbv(0) | SVSM_XCR0.load(Ordering::Relaxed);
        _xsetbv(0, xr0);
    }
}

fn xsave_enable() {
    if cpu_has_feat(Feature::Xsave) && cpu_has_feat(Feature::XsaveOpt) {
        if cpu_has_feat(Feature::Xcr0X87)
            && cpu_has_feat(Feature::Xcr0Sse)
            && cpu_has_feat(Feature::Xcr0Avx)
        {
            SVSM_XCR0.fetch_or(XCR0_YMM_ENABLE, Ordering::Relaxed);
        }
        cr4_xsave_enable();
        xcr0_set();
    } else {
        panic!("xsave unsupported");
    }
}

// Enable media and x87 instructions
pub fn sse_init() {
    legacy_sse_enable();
    xsave_enable();
}

/// # Safety
/// inline assembly here is used to save the SSE/FPU
/// context. This context store is specific to a task and
/// no other part of the code is accessing this memory at the same time.
pub unsafe fn sse_save_context(addr: u64) {
    let save_bits = SVSM_XCR0.load(Ordering::Relaxed);
    // SAFETY: Inline assembly used to save the SSE/FPU context. This context
    // store is specific to a task and no other part of the code is accessing
    // this memory at the same time.
    unsafe {
        asm!(
            r#"
            xsaveopt (%rsi)
            "#,
            in("rsi") addr,
            in("rax") save_bits,
            in("rdx") 0,
            options(att_syntax));
    }
}

/// # Safety
/// inline assembly here is used to restore the SSE/FPU
/// context. This context store is specific to a task and
/// no other part of the code is accessing this memory at the same time.
pub unsafe fn sse_restore_context(addr: u64) {
    let save_bits = SVSM_XCR0.load(Ordering::Relaxed);
    // SAFETY: Inline assembly used to restore the SSE/FPU context. This context
    // store is specific to a task and no other part of the code is accessing
    // this memory at the same time.
    unsafe {
        asm!(
            r#"
            xrstor (%rsi)
            "#,
            in("rsi") addr,
            in("rax") save_bits,
            in("rdx") 0,
            options(att_syntax));
    }
}
