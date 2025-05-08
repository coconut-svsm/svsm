// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use cpuarch::vmsa::VMSA;

#[derive(Copy, Clone, Debug)]
pub enum GuestRegister {
    X64Rax(u64),
    X64Rcx(u64),
    X64Rdx(u64),
    X64Rbx(u64),
    X64Rsp(u64),
    X64Rbp(u64),
    X64Rsi(u64),
    X64Rdi(u64),
    X64R8(u64),
    X64R9(u64),
    X64R10(u64),
    X64R11(u64),
    X64R12(u64),
    X64R13(u64),
    X64R14(u64),
    X64R15(u64),
}

pub fn set_guest_register(vmsa: &mut VMSA, reg: &GuestRegister) {
    match reg {
        GuestRegister::X64Rax(r) => vmsa.rax = *r,
        GuestRegister::X64Rcx(r) => vmsa.rcx = *r,
        GuestRegister::X64Rdx(r) => vmsa.rdx = *r,
        GuestRegister::X64Rbx(r) => vmsa.rbx = *r,
        GuestRegister::X64Rsp(r) => vmsa.rsp = *r,
        GuestRegister::X64Rbp(r) => vmsa.rbp = *r,
        GuestRegister::X64Rsi(r) => vmsa.rsi = *r,
        GuestRegister::X64Rdi(r) => vmsa.rdi = *r,
        GuestRegister::X64R8(r) => vmsa.r8 = *r,
        GuestRegister::X64R9(r) => vmsa.r9 = *r,
        GuestRegister::X64R10(r) => vmsa.r10 = *r,
        GuestRegister::X64R11(r) => vmsa.r11 = *r,
        GuestRegister::X64R12(r) => vmsa.r12 = *r,
        GuestRegister::X64R13(r) => vmsa.r13 = *r,
        GuestRegister::X64R14(r) => vmsa.r14 = *r,
        GuestRegister::X64R15(r) => vmsa.r15 = *r,
    }
}
