// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

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
#[derive(Default, Debug)]
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
