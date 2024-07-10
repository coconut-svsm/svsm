// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

use crate::cpu::control_regs::{cr0_sse_enable, cr4_osfxsr_enable, cr4_xsave_enable};
use crate::cpu::cpuid::CpuidResult;
use core::arch::x86_64::{_xgetbv, _xsetbv};

const CPUID_EDX_SSE1: u32 = 25;
const CPUID_ECX_XSAVE: u32 = 26;
const CPUID_EAX_XSAVEOPT: u32 = 0;
const XCR0_X87_ENABLE: u64 = 0x1;
const XCR0_SSE_ENABLE: u64 = 0x2;
const XCR0_YMM_ENABLE: u64 = 0x4;

fn legacy_sse_supported() -> bool {
    let res = CpuidResult::get(1, 0);
    (res.edx & (1 << CPUID_EDX_SSE1)) != 0
}

fn legacy_sse_enable() {
    if legacy_sse_supported() {
        cr4_osfxsr_enable();
        cr0_sse_enable();
    } else {
        panic!("Legacy SSE unsupported");
    }
}

fn extended_sse_supported() -> bool {
    let res = CpuidResult::get(0xD, 1);
    (res.eax & 0x7) == 0x7
}

fn xsave_supported() -> bool {
    let res = CpuidResult::get(1, 0);
    (res.ecx & (1 << CPUID_ECX_XSAVE)) != 0
}

fn xcr0_set() {
    unsafe {
        // set bits [0-2] in XCR0 to enable extended SSE
        let xr0 = _xgetbv(0) | XCR0_X87_ENABLE | XCR0_SSE_ENABLE | XCR0_YMM_ENABLE;
        _xsetbv(0, xr0);
    }
}

pub fn get_xsave_area_size() -> u32 {
    let res = CpuidResult::get(0xD, 0);
    if (res.eax & (1 << CPUID_EAX_XSAVEOPT)) == 0 {
        panic!("XSAVEOPT unsupported");
    }
    res.ecx
}

fn extended_sse_enable() {
    if extended_sse_supported() && xsave_supported() {
        cr4_xsave_enable();
        xcr0_set();
    } else {
        panic!("extended SSE unsupported");
    }
}

// Enable media and x87 instructions
pub fn sse_init() {
    legacy_sse_enable();
    extended_sse_enable();
}
