// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Register types used by the IGVM file format.

use crate::hv_defs::AlignedU128;
use crate::hv_defs::HvArm64RegisterName;
use crate::hv_defs::HvRegisterValue;
use crate::hv_defs::HvX64RegisterName;
use crate::hv_defs::HvX64SegmentRegister;
use crate::hv_defs::HvX64TableRegister;
use crate::hv_defs::Vtl;
use igvm_defs::VbsVpContextRegister;
use thiserror::Error;

/// An x86 Table register, like GDTR.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TableRegister {
    pub base: u64,
    pub limit: u16,
}

impl From<TableRegister> for HvRegisterValue {
    fn from(reg: TableRegister) -> Self {
        let hv_reg = HvX64TableRegister {
            pad: [0; 3],
            limit: reg.limit,
            base: reg.base,
        };

        hv_reg.into()
    }
}

impl From<HvX64TableRegister> for TableRegister {
    fn from(reg: HvX64TableRegister) -> Self {
        Self {
            base: reg.base,
            limit: reg.limit,
        }
    }
}

/// An x86 Segment Register, used for the segment selectors.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SegmentRegister {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub attributes: u16,
}

impl From<SegmentRegister> for HvRegisterValue {
    fn from(reg: SegmentRegister) -> Self {
        let hv_reg = HvX64SegmentRegister {
            base: reg.base,
            limit: reg.limit,
            selector: reg.selector,
            attributes: reg.attributes,
        };

        hv_reg.into()
    }
}

impl From<HvX64SegmentRegister> for SegmentRegister {
    fn from(reg: HvX64SegmentRegister) -> Self {
        Self {
            base: reg.base,
            limit: reg.limit,
            selector: reg.selector,
            attributes: reg.attributes,
        }
    }
}

/// x86 registers that can be stored in IGVM VP context structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86Register {
    Gdtr(TableRegister),
    Idtr(TableRegister),
    Ds(SegmentRegister),
    Es(SegmentRegister),
    Fs(SegmentRegister),
    Gs(SegmentRegister),
    Ss(SegmentRegister),
    Cs(SegmentRegister),
    Tr(SegmentRegister),
    Cr0(u64),
    Cr3(u64),
    Cr4(u64),
    Efer(u64),
    Pat(u64),
    Rbp(u64),
    Rip(u64),
    Rsi(u64),
    Rsp(u64),
    R8(u64),
    R9(u64),
    R10(u64),
    R11(u64),
    R12(u64),
    Rflags(u64),
    MtrrDefType(u64),
    MtrrPhysBase0(u64),
    MtrrPhysMask0(u64),
    MtrrPhysBase1(u64),
    MtrrPhysMask1(u64),
    MtrrPhysBase2(u64),
    MtrrPhysMask2(u64),
    MtrrPhysBase3(u64),
    MtrrPhysMask3(u64),
    MtrrPhysBase4(u64),
    MtrrPhysMask4(u64),
    MtrrFix64k00000(u64),
    MtrrFix16k80000(u64),
    // We do not currently have a need for the middle fixed MTRRs.
    MtrrFix4kE0000(u64),
    MtrrFix4kE8000(u64),
    MtrrFix4kF0000(u64),
    MtrrFix4kF8000(u64),
}

impl X86Register {
    pub fn into_vbs_vp_context_reg(&self, vtl: Vtl) -> VbsVpContextRegister {
        let (register_name, register_value): (_, HvRegisterValue) = match *self {
            X86Register::Gdtr(reg) => (HvX64RegisterName::Gdtr, reg.into()),
            X86Register::Idtr(reg) => (HvX64RegisterName::Idtr, reg.into()),
            X86Register::Ds(reg) => (HvX64RegisterName::Ds, reg.into()),
            X86Register::Es(reg) => (HvX64RegisterName::Es, reg.into()),
            X86Register::Fs(reg) => (HvX64RegisterName::Fs, reg.into()),
            X86Register::Gs(reg) => (HvX64RegisterName::Gs, reg.into()),
            X86Register::Ss(reg) => (HvX64RegisterName::Ss, reg.into()),
            X86Register::Cs(reg) => (HvX64RegisterName::Cs, reg.into()),
            X86Register::Tr(reg) => (HvX64RegisterName::Tr, reg.into()),
            X86Register::Cr0(reg) => (HvX64RegisterName::Cr0, reg.into()),
            X86Register::Cr3(reg) => (HvX64RegisterName::Cr3, reg.into()),
            X86Register::Cr4(reg) => (HvX64RegisterName::Cr4, reg.into()),
            X86Register::Efer(reg) => (HvX64RegisterName::Efer, reg.into()),
            X86Register::Pat(reg) => (HvX64RegisterName::Pat, reg.into()),
            X86Register::Rbp(reg) => (HvX64RegisterName::Rbp, reg.into()),
            X86Register::Rip(reg) => (HvX64RegisterName::Rip, reg.into()),
            X86Register::Rsi(reg) => (HvX64RegisterName::Rsi, reg.into()),
            X86Register::Rsp(reg) => (HvX64RegisterName::Rsp, reg.into()),
            X86Register::R8(reg) => (HvX64RegisterName::R8, reg.into()),
            X86Register::R9(reg) => (HvX64RegisterName::R9, reg.into()),
            X86Register::R10(reg) => (HvX64RegisterName::R10, reg.into()),
            X86Register::R11(reg) => (HvX64RegisterName::R11, reg.into()),
            X86Register::R12(reg) => (HvX64RegisterName::R12, reg.into()),
            X86Register::Rflags(reg) => (HvX64RegisterName::Rflags, reg.into()),
            X86Register::MtrrDefType(v) => (HvX64RegisterName::MsrMtrrDefType, v.into()),
            X86Register::MtrrPhysBase0(v) => (HvX64RegisterName::MsrMtrrPhysBase0, v.into()),
            X86Register::MtrrPhysMask0(v) => (HvX64RegisterName::MsrMtrrPhysMask0, v.into()),
            X86Register::MtrrPhysBase1(v) => (HvX64RegisterName::MsrMtrrPhysBase1, v.into()),
            X86Register::MtrrPhysMask1(v) => (HvX64RegisterName::MsrMtrrPhysMask1, v.into()),
            X86Register::MtrrPhysBase2(v) => (HvX64RegisterName::MsrMtrrPhysBase2, v.into()),
            X86Register::MtrrPhysMask2(v) => (HvX64RegisterName::MsrMtrrPhysMask2, v.into()),
            X86Register::MtrrPhysBase3(v) => (HvX64RegisterName::MsrMtrrPhysBase3, v.into()),
            X86Register::MtrrPhysMask3(v) => (HvX64RegisterName::MsrMtrrPhysMask3, v.into()),
            X86Register::MtrrPhysBase4(v) => (HvX64RegisterName::MsrMtrrPhysBase4, v.into()),
            X86Register::MtrrPhysMask4(v) => (HvX64RegisterName::MsrMtrrPhysMask4, v.into()),
            X86Register::MtrrFix64k00000(v) => (HvX64RegisterName::MsrMtrrFix64k00000, v.into()),
            X86Register::MtrrFix16k80000(v) => (HvX64RegisterName::MsrMtrrFix16k80000, v.into()),
            X86Register::MtrrFix4kE0000(v) => (HvX64RegisterName::MsrMtrrFix4kE0000, v.into()),
            X86Register::MtrrFix4kE8000(v) => (HvX64RegisterName::MsrMtrrFix4kE8000, v.into()),
            X86Register::MtrrFix4kF0000(v) => (HvX64RegisterName::MsrMtrrFix4kF0000, v.into()),
            X86Register::MtrrFix4kF8000(v) => (HvX64RegisterName::MsrMtrrFix4kF8000, v.into()),
        };

        VbsVpContextRegister {
            vtl: vtl as u8,
            register_name: register_name.0.into(),
            mbz: [0; 11],
            register_value: register_value.0.to_ne_bytes(),
        }
    }
}

/// AArch64 registers that can be stored in IGVM VP context structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AArch64Register {
    Pc(u64),
    X0(u64),
    X1(u64),
    Cpsr(u64),
    SctlrEl1(u64),
    TcrEl1(u64),
    MairEl1(u64),
    VbarEl1(u64),
    Ttbr0El1(u64),
    Ttbr1El1(u64),
}

impl AArch64Register {
    pub fn into_vbs_vp_context_reg(&self, vtl: Vtl) -> VbsVpContextRegister {
        let (register_name, register_value): (_, HvRegisterValue) = match *self {
            AArch64Register::Pc(reg) => (HvArm64RegisterName::XPc, reg.into()),
            AArch64Register::X0(reg) => (HvArm64RegisterName::X0, reg.into()),
            AArch64Register::X1(reg) => (HvArm64RegisterName::X1, reg.into()),
            AArch64Register::Cpsr(reg) => (HvArm64RegisterName::Cpsr, reg.into()),
            AArch64Register::SctlrEl1(reg) => (HvArm64RegisterName::SctlrEl1, reg.into()),
            AArch64Register::TcrEl1(reg) => (HvArm64RegisterName::TcrEl1, reg.into()),
            AArch64Register::MairEl1(reg) => (HvArm64RegisterName::MairEl1, reg.into()),
            AArch64Register::VbarEl1(reg) => (HvArm64RegisterName::VbarEl1, reg.into()),
            AArch64Register::Ttbr0El1(reg) => (HvArm64RegisterName::Ttbr0El1, reg.into()),
            AArch64Register::Ttbr1El1(reg) => (HvArm64RegisterName::Ttbr1El1, reg.into()),
        };

        VbsVpContextRegister {
            vtl: vtl as u8,
            register_name: register_name.0.into(),
            mbz: [0; 11],
            register_value: register_value.0.to_ne_bytes(),
        }
    }
}

#[derive(Debug, Error)]
#[error("unsupported register {0:#x?}")]
pub struct UnsupportedRegister<T>(T);

impl TryFrom<igvm_defs::VbsVpContextRegister> for X86Register {
    type Error = UnsupportedRegister<HvX64RegisterName>;

    fn try_from(value: igvm_defs::VbsVpContextRegister) -> Result<Self, Self::Error> {
        // Copy register_value out to its own field to remove reference to packed unaligned field
        let register_value = HvRegisterValue(AlignedU128::from_ne_bytes(value.register_value));

        let reg = match HvX64RegisterName(value.register_name.get()) {
            HvX64RegisterName::Gdtr => Self::Gdtr(register_value.as_table().into()),
            HvX64RegisterName::Idtr => Self::Idtr(register_value.as_table().into()),
            HvX64RegisterName::Ds => Self::Ds(register_value.as_segment().into()),
            HvX64RegisterName::Es => Self::Es(register_value.as_segment().into()),
            HvX64RegisterName::Fs => Self::Fs(register_value.as_segment().into()),
            HvX64RegisterName::Gs => Self::Gs(register_value.as_segment().into()),
            HvX64RegisterName::Ss => Self::Ss(register_value.as_segment().into()),
            HvX64RegisterName::Cs => Self::Cs(register_value.as_segment().into()),
            HvX64RegisterName::Tr => Self::Tr(register_value.as_segment().into()),
            HvX64RegisterName::Cr0 => Self::Cr0(register_value.as_u64()),
            HvX64RegisterName::Cr3 => Self::Cr3(register_value.as_u64()),
            HvX64RegisterName::Cr4 => Self::Cr4(register_value.as_u64()),
            HvX64RegisterName::Efer => Self::Efer(register_value.as_u64()),
            HvX64RegisterName::Pat => Self::Pat(register_value.as_u64()),
            HvX64RegisterName::Rbp => Self::Rbp(register_value.as_u64()),
            HvX64RegisterName::Rip => Self::Rip(register_value.as_u64()),
            HvX64RegisterName::Rsi => Self::Rsi(register_value.as_u64()),
            HvX64RegisterName::Rsp => Self::Rsp(register_value.as_u64()),
            HvX64RegisterName::R8 => Self::R8(register_value.as_u64()),
            HvX64RegisterName::R9 => Self::R9(register_value.as_u64()),
            HvX64RegisterName::R10 => Self::R10(register_value.as_u64()),
            HvX64RegisterName::R11 => Self::R11(register_value.as_u64()),
            HvX64RegisterName::R12 => Self::R12(register_value.as_u64()),
            HvX64RegisterName::Rflags => Self::Rflags(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrDefType => Self::MtrrDefType(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrPhysBase0 => Self::MtrrPhysBase0(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrPhysMask0 => Self::MtrrPhysMask0(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrPhysBase1 => Self::MtrrPhysBase1(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrPhysMask1 => Self::MtrrPhysMask1(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrPhysBase2 => Self::MtrrPhysBase2(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrPhysMask2 => Self::MtrrPhysMask2(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrPhysBase3 => Self::MtrrPhysBase3(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrPhysMask3 => Self::MtrrPhysMask3(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrPhysBase4 => Self::MtrrPhysBase4(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrPhysMask4 => Self::MtrrPhysMask4(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrFix64k00000 => Self::MtrrFix64k00000(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrFix16k80000 => Self::MtrrFix16k80000(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrFix4kE0000 => Self::MtrrFix4kE0000(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrFix4kE8000 => Self::MtrrFix4kE8000(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrFix4kF0000 => Self::MtrrFix4kF0000(register_value.as_u64()),
            HvX64RegisterName::MsrMtrrFix4kF8000 => Self::MtrrFix4kF8000(register_value.as_u64()),
            other => return Err(UnsupportedRegister(other)),
        };

        Ok(reg)
    }
}

impl TryFrom<igvm_defs::VbsVpContextRegister> for AArch64Register {
    type Error = UnsupportedRegister<HvArm64RegisterName>;

    fn try_from(value: igvm_defs::VbsVpContextRegister) -> Result<Self, Self::Error> {
        // Copy register_value out to its own field to remove reference to packed unaligned field
        let register_value = HvRegisterValue(AlignedU128::from_ne_bytes(value.register_value));

        let reg = match HvArm64RegisterName(value.register_name.get()) {
            HvArm64RegisterName::XPc => Self::Pc(register_value.as_u64()),
            HvArm64RegisterName::X0 => Self::X0(register_value.as_u64()),
            HvArm64RegisterName::X1 => Self::X1(register_value.as_u64()),
            HvArm64RegisterName::Cpsr => Self::Cpsr(register_value.as_u64()),
            HvArm64RegisterName::SctlrEl1 => Self::SctlrEl1(register_value.as_u64()),
            HvArm64RegisterName::TcrEl1 => Self::TcrEl1(register_value.as_u64()),
            HvArm64RegisterName::MairEl1 => Self::MairEl1(register_value.as_u64()),
            HvArm64RegisterName::VbarEl1 => Self::VbarEl1(register_value.as_u64()),
            HvArm64RegisterName::Ttbr0El1 => Self::Ttbr0El1(register_value.as_u64()),
            HvArm64RegisterName::Ttbr1El1 => Self::Ttbr1El1(register_value.as_u64()),
            other => return Err(UnsupportedRegister(other)),
        };

        Ok(reg)
    }
}
