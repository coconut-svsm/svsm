// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

use crate::cpu::control_regs::{cr0_sse_enable, cr4_osfxsr_enable, cr4_xsave_enable};
use crate::cpu::features::{Feature, cpu_has_feat};
use crate::platform::cpuid;
use core::arch::asm;
use core::arch::x86_64::{_xgetbv, _xsetbv};
use core::sync::atomic::{AtomicU64, Ordering};
use cpufeature::CpuidFeature;
use cpufeature::leaves::XSAVE_SZ;
const XCR0_X87_ENABLE: u64 = 0x1;
const XCR0_SSE_ENABLE: u64 = 0x2;
const XCR0_YMM_ENABLE: u64 = 0x4;

// XSAVE size for x87 + SSE
pub const XSAVE_LEGACY_SIZE: u32 = 0x240;

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

/// Compute the XSAVE area size for the currently enabled features.
///
/// Rather than relying on the CPUID page having entries indexed by the
/// runtime XCR0 value, compute the size from CPUID leaf 0xD subleaves
/// 2-63, which describe individual XSAVE components independently of
/// XCR0 (AMD APM Vol. 3, Appendix E.3.10). This avoids needing an entry
/// in the CPUID page for every potential XCR0 value.
pub fn xsave_area_size() -> u32 {
    let xcr0 = SVSM_XCR0.load(Ordering::Relaxed);
    let mut size = XSAVE_LEGACY_SIZE;

    for bit in 2..64 {
        if xcr0 & (1u64 << bit) == 0 {
            continue;
        }
        let feature = CpuidFeature {
            subleaf: bit,
            ..XSAVE_SZ
        };
        let Some(result) = cpuid(&feature) else {
            log::warn!("FP feature {bit:#x} enabled but not present in CPUID");
            continue;
        };
        // We only use the non-compacted format for now.
        // EBX is the offset within the XSAVE area, EAX is the size
        // starting from the offset.
        size = size.max(result.ebx + result.eax);
    }

    size
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
