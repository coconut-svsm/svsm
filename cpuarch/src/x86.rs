// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use bitflags::bitflags;

pub const MSR_EFER: u32 = 0xC000_0080;

bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct EFERFlags: u64 {
        const SCE   = 1 << 0;  // System Call Extensions
        const LME   = 1 << 8;  // Long Mode Enable
        const LMA   = 1 << 10; // Long Mode Active
        const NXE   = 1 << 11; // No-Execute Enable
        const SVME  = 1 << 12; // Secure Virtual Machine Enable
        const LMSLE = 1 << 13; // Long Mode Segment Limit Enable
        const FFXSR = 1 << 14; // Fast FXSAVE/FXRSTOR
        const TCE   = 1 << 15; // Translation Cache Extension
        const MCOMMIT   = 1 << 17; // Enable MCOMMIT instruction
        const INTWB = 1 << 18; // Interruptible WBINVD/WBNOINVD enable
        const UAIE  = 1 << 20; // Upper Address Ignore Enable
    }
}

impl From<usize> for EFERFlags {
    fn from(bits: usize) -> Self {
        EFERFlags::from_bits_truncate(bits as u64)
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
        const FSGSBASE      = 1 << 16; // Enable RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE instructions
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
