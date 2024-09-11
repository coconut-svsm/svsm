// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use bitflags::bitflags;

#[repr(C, packed)]
#[derive(Default, Debug, Clone, Copy)]
pub struct X86GeneralRegs {
    pub r15: usize,
    pub r14: usize,
    pub r13: usize,
    pub r12: usize,
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rbp: usize,
    pub rdi: usize,
    pub rsi: usize,
    pub rdx: usize,
    pub rcx: usize,
    pub rbx: usize,
    pub rax: usize,
}

#[repr(C, packed)]
#[derive(Default, Debug, Clone, Copy)]
pub struct X86SegmentRegs {
    pub cs: usize,
    pub ds: usize,
    pub es: usize,
    pub fs: usize,
    pub gs: usize,
    pub ss: usize,
}

#[repr(C, packed)]
#[derive(Default, Debug, Clone, Copy)]
pub struct X86InterruptFrame {
    pub rip: usize,
    pub cs: usize,
    pub flags: usize,
    pub rsp: usize,
    pub ss: usize,
}

bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq)]
    pub struct SegDescAttrFlags: u64 {
        const A     = 1 << 40;
        const R_W   = 1 << 41;
        const C_E   = 1 << 42;
        const C_D   = 1 << 43;
        const S     = 1 << 44;
        const AVL   = 1 << 52;
        const L     = 1 << 53;
        const DB    = 1 << 54;
        const G     = 1 << 55;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct RFlags: usize {
        const CF    = 1 << 0;
        const FIXED = 1 << 1;
        const PF    = 1 << 2;
        const AF    = 1 << 4;
        const ZF    = 1 << 6;
        const SF    = 1 << 7;
        const TF    = 1 << 8;
        const IF    = 1 << 9;
        const DF    = 1 << 10;
        const OF    = 1 << 11;
        const IOPL  = 3 << 12;
        const NT    = 1 << 14;
        const MD    = 1 << 15;
        const RF    = 1 << 16;
        const VM    = 1 << 17;
        const AC    = 1 << 18;
        const VIF   = 1 << 19;
        const VIP   = 1 << 20;
        const ID    = 1 << 21;
    }
}
