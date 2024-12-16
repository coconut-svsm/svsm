// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::features::cpu_has_pge;
use crate::address::{Address, PhysAddr};
use crate::cpu::features::{cpu_has_smap, cpu_has_smep};
use crate::platform::SvsmPlatform;
use bitflags::bitflags;
use core::arch::asm;

#[inline]
pub fn cr0_init() {
    let mut cr0 = read_cr0();

    cr0.insert(CR0Flags::WP); // Enable Write Protection
    cr0.remove(CR0Flags::NW); // Enable caches ...
    cr0.remove(CR0Flags::CD); // ... if not already happened

    // SAFETY: we are not changing any execution-state relevant flags
    unsafe {
        write_cr0(cr0);
    }
}

#[inline]
pub fn cr4_init(platform: &dyn SvsmPlatform) {
    let mut cr4 = read_cr4();

    cr4.insert(CR4Flags::PSE); // Enable Page Size Extensions

    // All processors that are capable of virtualization will support global
    // page table entries, so there is no reason to support any processor that
    // does not enumerate PGE capability.
    assert!(cpu_has_pge(platform), "CPU does not support PGE");

    cr4.insert(CR4Flags::PGE); // Enable Global Pages

    if !cfg!(feature = "nosmep") {
        assert!(cpu_has_smep(platform), "CPU does not support SMEP");
        cr4.insert(CR4Flags::SMEP);
    }

    if !cfg!(feature = "nosmap") {
        assert!(cpu_has_smap(platform), "CPU does not support SMAP");
        cr4.insert(CR4Flags::SMAP);
    }

    // SAFETY: we are not changing any execution-state relevant flags
    unsafe {
        write_cr4(cr4);
    }
}

#[inline]
pub fn cr0_sse_enable() {
    let mut cr0 = read_cr0();

    cr0.insert(CR0Flags::MP);
    cr0.remove(CR0Flags::EM);

    // No Lazy context switching
    cr0.remove(CR0Flags::TS);

    // SAFETY: we are not changing any execution-state relevant flags
    unsafe {
        write_cr0(cr0);
    }
}

#[inline]
pub fn cr4_osfxsr_enable() {
    let mut cr4 = read_cr4();

    cr4.insert(CR4Flags::OSFXSR);

    // SAFETY: we are not changing any execution-state relevant flags
    unsafe {
        write_cr4(cr4);
    }
}

#[inline]
pub fn cr4_xsave_enable() {
    let mut cr4 = read_cr4();

    cr4.insert(CR4Flags::OSXSAVE);

    // SAFETY: we are not changing any execution-state relevant flags
    unsafe {
        write_cr4(cr4);
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct CR0Flags: u64 {
        const PE = 1 << 0;  // Protection Enabled
        const MP = 1 << 1;  // Monitor Coprocessor
        const EM = 1 << 2;  // Emulation
        const TS = 1 << 3;  // Task Switched
        const ET = 1 << 4;  // Extension Type
        const NE = 1 << 5;  // Numeric Error
        const WP = 1 << 16; // Write Protect
        const AM = 1 << 18; // Alignment Mask
        const NW = 1 << 29; // Not Writethrough
        const CD = 1 << 30; // Cache Disable
        const PG = 1 << 31; // Paging
    }
}

impl From<usize> for CR0Flags {
    fn from(bits: usize) -> Self {
        CR0Flags::from_bits_truncate(bits as u64)
    }
}

#[inline]
pub fn read_cr0() -> CR0Flags {
    let cr0: u64;

    // SAFETY: The inline assembly just reads the processors CR0 register
    // and does not change any state.
    unsafe {
        asm!("mov %cr0, %rax",
             out("rax") cr0,
             options(att_syntax));
    }

    CR0Flags::from_bits_truncate(cr0)
}

/// # Safety
///
/// The caller must ensure to not change any execution-state relevant flags
/// like PE or PG.
#[inline]
pub unsafe fn write_cr0(cr0: CR0Flags) {
    let reg = cr0.bits();

    // SAFETY: The inline assembly set the processors CR0 register with flags
    // defined by `struct CR0Flags`. The caller must ensure to not change any
    // execution-state relevant flags.
    unsafe {
        asm!("mov %rax, %cr0",
             in("rax") reg,
             options(att_syntax));
    }
}

#[inline]
pub fn read_cr2() -> usize {
    let ret: usize;

    // SAFETY: The inline assembly just reads the processors CR2 register
    // and does not change any state.
    unsafe {
        asm!("mov %cr2, %rax",
             out("rax") ret,
             options(att_syntax));
    }
    ret
}

#[inline]
pub fn read_cr3() -> PhysAddr {
    let ret: usize;

    // SAFETY: The inline assembly just reads the processors CR3 register
    // and does not change any state.
    unsafe {
        asm!("mov %cr3, %rax",
             out("rax") ret,
             options(att_syntax));
    }
    PhysAddr::from(ret)
}

/// # Safety
///
/// The caller must ensure to take other actions to make sure a memory safe
/// execution state is warranted (e.g. changing the stack and register state).
#[inline]
pub unsafe fn write_cr3(cr3: PhysAddr) {
    // SAFETY: The inline assembly set the processors CR3 register. The safety
    // of the CR3 value is delegated to the caller of this function which is unsafe.
    unsafe {
        asm!("mov %rax, %cr3",
             in("rax") cr3.bits(),
             options(att_syntax));
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct CR4Flags: u64 {
        const VME       = 1 << 0;  // Virtual-8086 Mode Extensions
        const PVI       = 1 << 1;  // Protected-Mode Virtual Interrupts
        const TSD       = 1 << 2;  // Time Stamp Disable
        const DE        = 1 << 3;  // Debugging Extensions
        const PSE       = 1 << 4;  // Page Size Extensions
        const PAE       = 1 << 5;  // Physical-Address Extension
        const MCE       = 1 << 6;  // Machine Check Enable
        const PGE       = 1 << 7;  // Page-Global Enable
        const PCE       = 1 << 8;  // Performance-Monitoring Counter Enable
        const OSFXSR        = 1 << 9;  // Operating System FXSAVE/FXRSTOR Support
        const OSXMMEXCPT    = 1 << 10; // Operating System Unmasked Exception Support
        const UMIP      = 1 << 11; // User Mode Instruction Prevention
        const LA57      = 1 << 12; // 57-bit linear address
        const FSGSBASE      = 1 << 16; // Enable RDFSBASE, RDGSBASE, WRFSBASE, and
                           // WRGSBASE instructions
        const PCIDE     = 1 << 17; // Process Context Identifier Enable
        const OSXSAVE       = 1 << 18; // XSAVE and Processor Extended States Enable Bit
        const SMEP      = 1 << 20; // Supervisor Mode Execution Prevention
        const SMAP      = 1 << 21; // Supervisor Mode Access Protection
        const PKE       = 1 << 22; // Protection Key Enable
        const CET       = 1 << 23; // Control-flow Enforcement Technology
    }
}

impl From<usize> for CR4Flags {
    fn from(bits: usize) -> Self {
        CR4Flags::from_bits_truncate(bits as u64)
    }
}

#[inline]
pub fn read_cr4() -> CR4Flags {
    let cr4: u64;

    // SAFETY: The inline assembly just reads the processors CR4 register
    // and does not change any state.
    unsafe {
        asm!("mov %cr4, %rax",
             out("rax") cr4,
             options(att_syntax));
    }

    CR4Flags::from_bits_truncate(cr4)
}

/// # Safety
///
/// The caller must ensure to not change any execution-state relevant flags
/// (e.g. PSE or PAE).
#[inline]
pub unsafe fn write_cr4(cr4: CR4Flags) {
    let reg = cr4.bits();

    // SAFETY: The inline assembly set the processors CR4 register with flags
    // defined by `struct CR4Flags`. The caller must ensure to not change any
    // execution-state relevant flags.
    unsafe {
        asm!("mov %rax, %cr4",
             in("rax") reg,
             options(att_syntax));
    }
}
