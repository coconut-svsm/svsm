// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 SUSE LLC
//
// Author: Carlos López <clopez@suse.de>

use std::{
    arch::x86_64::{__cpuid, CpuidResult},
    process::ExitCode,
};

use bitfield_struct::bitfield;

// AMD Programmer's Manual Volume 3
// - Section "Function 8000_0000h - Maximum Extended Function Number and Vendor String"
// - Section "Function 8000_001Fh - Encrypted Memory Capabilities"
const CPUID_MAX_EXTENDED_LEAF: u32 = 0x80000000;
const CPUID_ENCRYPT_MEM_CAPAB: u32 = 0x8000001f;

#[bitfield(u32)]
struct EncryptMemCapEax {
    sme: bool,
    sev: bool,
    #[bits(30)]
    _unused: u32,
}

#[bitfield(u32)]
struct EncryptMemCapEbx {
    #[bits(6)]
    cbit: u8,
    #[bits(6)]
    phys_addr_reduction: u8,
    #[bits(4)]
    vmpls: u8,
    _reserved: u16,
}

fn cpuid(eax: u32) -> CpuidResult {
    // SAFETY: CPUID is always safe
    unsafe { __cpuid(eax) }
}

fn main() -> ExitCode {
    let res = cpuid(CPUID_MAX_EXTENDED_LEAF);
    if res.eax < CPUID_ENCRYPT_MEM_CAPAB {
        return ExitCode::FAILURE;
    }

    let res = cpuid(CPUID_ENCRYPT_MEM_CAPAB);
    let cap1 = EncryptMemCapEax::from(res.eax);
    if !cap1.sev() {
        return ExitCode::FAILURE;
    }

    let cap2 = EncryptMemCapEbx::from(res.ebx);
    println!("{} {}", cap2.cbit(), cap2.phys_addr_reduction());

    ExitCode::SUCCESS
}
