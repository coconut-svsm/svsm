// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023, 2026 SUSE LLC
//
// Authors: Joerg Roedel <jroedel@suse.de>
//          Carlos López <clopez@suse.de>

use crate::platform::cpuid;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use cpufeature::CpuidFeature;
use cpufeature::CpuidRegister;
use cpufeature::leaves::{
    CET_SS, INVLPGB_MAX_PAGES, PTE_CBIT_POS, X86_FEATURE_PGE, X86_FEATURE_SMAP, X86_FEATURE_SMEP,
    X86_FEATURE_UMIP, X86_FEATURE_X2APIC, X86_FEATURE_XMM, X86_FEATURE_XSAVE, X86_FEATURE_XSAVEOPT,
    XCR0_AVX, XCR0_SSE, XCR0_X87,
};

/// CPUID leaf 0 — CPU vendor ID string (EBX/ECX/EDX).
///
/// Not exposed under that name in the cpufeature database (leaf 0 is
/// `MAX_STD_LEAF` on EAX), so keep a local descriptor for vendor detection.
pub const CPU_VENDOR_ID: CpuidFeature = CpuidFeature {
    leaf: 0,
    subleaf: 0,
    register: CpuidRegister::Edx,
    shift: 0,
    width: 32,
};

/// Raw EAX from CPUID leaf 0x8000_0008 — processor capacity parameters.
/// Not in the cpufeature database as a full-register field (only the individual
/// bit ranges are), so keep a local descriptor for the full EAX value.
const PHYS_ADDR_SIZES: CpuidFeature = CpuidFeature {
    leaf: 0x8000_0008,
    subleaf: 0,
    register: CpuidRegister::Eax,
    shift: 0,
    width: 32,
};

/// CPUID.4000_0001:EAX — Hyper-V interface signature ("Hv#1").
const HYPERV_INTERFACE: CpuidFeature = CpuidFeature {
    leaf: 0x4000_0001,
    subleaf: 0,
    register: CpuidRegister::Eax,
    shift: 0,
    width: 32,
};

const HYPERV_INTERFACE_SIGNATURE: u32 = 0x3123_7648;

/// A discoverable CPU feature.
///
/// At the moment this type is used for CPUID detection, but it can
/// be expanded to use other sources of information.
#[derive(Debug)]
struct CpuFeat {
    /// Raw value
    val: ImmutAfterInitCell<u32>,
    /// Location of the feature within a CPUID leaf
    feature: CpuidFeature,
    /// Expected value after shift + mask
    expected: u32,
}

impl CpuFeat {
    /// Create a new feature, indicated by a single bit (expected value 1).
    const fn new_bit(feature: CpuidFeature) -> Self {
        Self::new(feature, 1)
    }

    /// Create a new CPU feature from a cpufeature descriptor, comparing the
    /// extracted field against the given expected value.
    const fn new(feature: CpuidFeature, expected: u32) -> Self {
        Self {
            val: ImmutAfterInitCell::uninit(),
            feature,
            expected,
        }
    }

    fn get_or_init(&self) -> u32 {
        if let Ok(val) = self.val.try_get_inner() {
            return *val;
        }
        let val = cpuid(&self.feature).map_or(0, |c| {
            self.feature.register.select(c.eax, c.ebx, c.ecx, c.edx)
        });
        // If init() fails it means the cell got initialized by someone else
        // concurrently, which is always benign.
        let _ = self.val.init(val);
        val
    }

    /// Gets the raw value of this feature, lazily querying CPUID if
    /// the value is not cached from a previous query
    fn get(&self) -> u32 {
        let mask = ((1u64 << self.feature.width) as u32).wrapping_sub(1);
        (self.get_or_init() >> self.feature.shift) & mask
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
    X2Apic => CpuFeat::new_bit(X86_FEATURE_X2APIC),
    Xsave => CpuFeat::new_bit(X86_FEATURE_XSAVE),
    Pge => CpuFeat::new_bit(X86_FEATURE_PGE),
    Sse1 => CpuFeat::new_bit(X86_FEATURE_XMM),
    Smep => CpuFeat::new_bit(X86_FEATURE_SMEP),
    Smap => CpuFeat::new_bit(X86_FEATURE_SMAP),
    Umip => CpuFeat::new_bit(X86_FEATURE_UMIP),
    CetSS => CpuFeat::new_bit(CET_SS),
    Xcr0X87 => CpuFeat::new_bit(XCR0_X87),
    Xcr0Sse => CpuFeat::new_bit(XCR0_SSE),
    Xcr0Avx => CpuFeat::new_bit(XCR0_AVX),
    XsaveOpt => CpuFeat::new_bit(X86_FEATURE_XSAVEOPT),
    HyperV => CpuFeat::new(HYPERV_INTERFACE, HYPERV_INTERFACE_SIGNATURE),
    PhysAddrSizes => CpuFeat::new(PHYS_ADDR_SIZES, 0),
    InvlpgbMax => CpuFeat::new(INVLPGB_MAX_PAGES, 0),
    Cbit => CpuFeat::new(PTE_CBIT_POS, 0),
}
