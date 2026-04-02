// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023, 2026 SUSE LLC
//
// Authors: Joerg Roedel <jroedel@suse.de>
//          Carlos López <clopez@suse.de>

use core::arch::x86_64::CpuidResult;

use crate::{platform::cpuid, utils::immut_after_init::ImmutAfterInitCell};

/// The CPUID output register for a particular feature
#[derive(Clone, Copy, Debug)]
enum CpuidReg {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

/// A discoverable CPU feature.
///
/// At the moment this type is used for CPUID detection, but it can
/// be expanded to use other sources of information.
#[derive(Debug)]
struct CpuFeat {
    /// Raw value
    val: ImmutAfterInitCell<u32>,
    /// CPUID leaf
    leaf: u32,
    /// CPUID subleaf
    subleaf: u32,
    /// CPUID output register
    reg: CpuidReg,
    /// Bitshift to apply to raw value
    shift: u8,
    /// Bitmask to apply to raw value
    bitsize: u8,
    /// Expected value after shift + mask
    expected: u32,
}

impl CpuFeat {
    /// Create a new feature, indicated by a single bit in the specified
    /// register in the given CPUID leaf.
    const fn new_bit(leaf: u32, reg: CpuidReg, bit: u8) -> Self {
        Self::new(leaf, reg, bit, 1, 1)
    }

    /// Create a new feature, indicated by the full value of a register
    /// in the given CPUID leaf.
    const fn new_u32(leaf: u32, reg: CpuidReg, expected: u32) -> Self {
        Self::new(leaf, reg, 0, u32::BITS as u8, expected)
    }

    /// Create a new CPU feature, detected by querying the given CPUID leaf, and applying
    /// a bitshift and bitmask on the specified output register to compare it to the given
    /// expected value.
    const fn new(leaf: u32, reg: CpuidReg, shift: u8, bitsize: u8, expected: u32) -> Self {
        // This method is only called from const context, so these assertions have no
        // runtime effect.
        assert!((shift as u32) < u32::BITS);
        assert!((bitsize as u32) <= u32::BITS);
        Self {
            val: ImmutAfterInitCell::uninit(),
            leaf,
            subleaf: 0,
            reg,
            shift,
            bitsize,
            expected,
        }
    }

    /// Create a copy of the given CPU feature, but with the specified
    /// subleaf.
    const fn with_subfn(mut self, subleaf: u32) -> Self {
        self.subleaf = subleaf;
        self
    }

    /// Get the CPUID register that corresponds to this feature
    const fn get_reg(&self, cpuid: &CpuidResult) -> u32 {
        match self.reg {
            CpuidReg::Eax => cpuid.eax,
            CpuidReg::Ebx => cpuid.ebx,
            CpuidReg::Ecx => cpuid.ecx,
            CpuidReg::Edx => cpuid.edx,
        }
    }

    const fn mask(&self) -> u32 {
        ((1u64 << self.bitsize) - 1) as u32
    }

    fn get_or_init(&self) -> u32 {
        if let Ok(val) = self.val.try_get_inner() {
            return *val;
        }
        let val = cpuid(self.leaf, self.subleaf).map_or(0, |c| self.get_reg(&c));
        // If init() fails it means the cell got initialized by someone else
        // concurrently, which is always benign.
        let _ = self.val.init(val);
        val
    }

    /// Gets the raw value of this feature, lazily querying CPUID if
    /// the value is not cached from a previous query
    fn get(&self) -> u32 {
        (self.get_or_init() >> self.shift) & self.mask()
    }

    /// Checks whether this feature is available by comparing it to
    /// its expected value, lazily querying CPUID if the value is not
    /// cached from a previous query
    fn enabled(&self) -> bool {
        self.get() == self.expected
    }
}

/// Macro to generate a CPU feature lookup table
macro_rules! define_cpu_feats {
    (
        $(
            $variant:ident => $feat_expr:expr
        ),* $(,)?
    ) => {

        // Feature enum to use as index
        #[repr(usize)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Feature {
            $( $variant, )*
        }

        /// The number of defined features
        const NUM_FEATS: usize = [ $( stringify!($variant) ),* ].len();

        static CPU_FEATS: [CpuFeat; NUM_FEATS] = [
            $( $feat_expr, )*
        ];
    };
}

/// Check if the given feature is enabled by comparing it to its expected
/// value.
pub fn cpu_has_feat(feat: Feature) -> bool {
    // Because of #[repr(usize)], this cast matches the array index perfectly.
    CPU_FEATS[feat as usize].enabled()
}

/// Gets the raw value of the given feature
pub fn cpu_get_feat(feat: Feature) -> u32 {
    CPU_FEATS[feat as usize].get()
}

define_cpu_feats! {
    Xsave => CpuFeat::new_bit(0x0000_0001, CpuidReg::Ecx, 26),
    Pge => CpuFeat::new_bit(0x0000_0001, CpuidReg::Edx, 13),
    Sse1 => CpuFeat::new_bit(0x0000_0001, CpuidReg::Edx, 25),
    Smep => CpuFeat::new_bit(0x0000_0007, CpuidReg::Ebx, 7),
    Smap => CpuFeat::new_bit(0x0000_0007, CpuidReg::Ebx, 20),
    Umip => CpuFeat::new_bit(0x0000_0007, CpuidReg::Ecx, 2),
    CetSS => CpuFeat::new_bit(0x0000_0007, CpuidReg::Ecx, 7),
    Xcr0X87 => CpuFeat::new_bit(0x0000_000d, CpuidReg::Eax, 0),
    Xcr0Sse => CpuFeat::new_bit(0x0000_000d, CpuidReg::Eax, 1),
    Xcr0Avx => CpuFeat::new_bit(0x0000_000d, CpuidReg::Eax, 2),
    XsaveSize => CpuFeat::new_u32(0x0000_000d, CpuidReg::Ecx, 0),
    XsaveOpt => CpuFeat::new_bit(0x0000_000d, CpuidReg::Eax, 0).with_subfn(1),
    HyperV => CpuFeat::new_u32(0x40000001, CpuidReg::Eax, 0x31237648),
    PhysAddrSizes => CpuFeat::new_u32(0x80000008, CpuidReg::Eax, 0),
    InvlpgbMax => CpuFeat::new(0x80000008, CpuidReg::Edx, 0, u16::BITS as u8, 0),
}
