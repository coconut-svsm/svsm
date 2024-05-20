// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Thomas Leroy <tleroy@suse.de>

use super::decode::DecodedInsnCtx;
use super::{InsnError, InsnMachineCtx};
use crate::types::Bytes;

/// An immediate value in an instruction
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Immediate {
    U8(u8),
    U16(u16),
    U32(u32),
}

/// A register in an instruction
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Register {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
}

/// A Segment register in instruction
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegRegister {
    CS,
    SS,
    DS,
    ES,
    FS,
    GS,
}

/// An operand in an instruction, which might be a register or an immediate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operand {
    Reg(Register),
    Imm(Immediate),
}

impl Operand {
    #[inline]
    pub const fn rdx() -> Self {
        Self::Reg(Register::Rdx)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedInsn {
    Cpuid,
    In(Operand, Bytes),
    Out(Operand, Bytes),
    Wrmsr,
    Rdmsr,
    Rdtsc,
    Rdtscp,
}

pub const MAX_INSN_SIZE: usize = 15;

/// A view of an x86 instruction.
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub struct Instruction([u8; MAX_INSN_SIZE]);

impl Instruction {
    pub const fn new(bytes: [u8; MAX_INSN_SIZE]) -> Self {
        Self(bytes)
    }

    /// Decode the instruction with the given InsnMachineCtx.
    ///
    /// # Returns
    ///
    /// A [`DecodedInsnCtx`] if the instruction is supported, or an [`InsnError`] otherwise.
    pub fn decode<I: InsnMachineCtx>(&self, mctx: &I) -> Result<DecodedInsnCtx, InsnError> {
        DecodedInsnCtx::new(&self.0, mctx)
    }
}

/// A dummy struct to implement InsnMachineCtx for testing purposes.
#[cfg(any(test, fuzzing))]
#[derive(Copy, Clone, Debug)]
pub struct TestCtx;

#[cfg(any(test, fuzzing))]
impl InsnMachineCtx for TestCtx {
    fn read_efer(&self) -> u64 {
        use crate::cpu::efer::EFERFlags;

        EFERFlags::LMA.bits()
    }

    fn read_seg(&self, seg: SegRegister) -> u64 {
        match seg {
            SegRegister::CS => 0x00af9a000000ffffu64,
            _ => 0x00cf92000000ffffu64,
        }
    }

    fn read_cr0(&self) -> u64 {
        use crate::cpu::control_regs::CR0Flags;

        CR0Flags::PE.bits()
    }

    fn read_cr4(&self) -> u64 {
        use crate::cpu::control_regs::CR4Flags;

        CR4Flags::LA57.bits()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_inb() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xE4, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&TestCtx).unwrap();
        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::In(Operand::Imm(Immediate::U8(0x41)), Bytes::One)
        );
        assert_eq!(decoded.size(), 2);

        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xEC, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&TestCtx).unwrap();
        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::In(Operand::rdx(), Bytes::One)
        );
        assert_eq!(decoded.size(), 1);
    }

    #[test]
    fn test_decode_inw() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0xE5, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::In(Operand::Imm(Immediate::U8(0x41)), Bytes::Two)
        );
        assert_eq!(decoded.size(), 3);

        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0xED, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::In(Operand::rdx(), Bytes::Two)
        );
        assert_eq!(decoded.size(), 2);
    }

    #[test]
    fn test_decode_inl() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xE5, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::In(Operand::Imm(Immediate::U8(0x41)), Bytes::Four)
        );
        assert_eq!(decoded.size(), 2);

        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xED, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::In(Operand::rdx(), Bytes::Four)
        );
        assert_eq!(decoded.size(), 1);
    }

    #[test]
    fn test_decode_outb() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xE6, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::Out(Operand::Imm(Immediate::U8(0x41)), Bytes::One)
        );
        assert_eq!(decoded.size(), 2);

        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xEE, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::Out(Operand::rdx(), Bytes::One)
        );
        assert_eq!(decoded.size(), 1);
    }

    #[test]
    fn test_decode_outw() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0xE7, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::Out(Operand::Imm(Immediate::U8(0x41)), Bytes::Two)
        );
        assert_eq!(decoded.size(), 3);

        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0xEF, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::Out(Operand::rdx(), Bytes::Two)
        );
        assert_eq!(decoded.size(), 2);
    }

    #[test]
    fn test_decode_outl() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xE7, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::Out(Operand::Imm(Immediate::U8(0x41)), Bytes::Four)
        );
        assert_eq!(decoded.size(), 2);

        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xEF, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::Out(Operand::rdx(), Bytes::Four)
        );
        assert_eq!(decoded.size(), 1);
    }

    #[test]
    fn test_decode_cpuid() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x0F, 0xA2, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Cpuid);
        assert_eq!(decoded.size(), 2);
    }

    #[test]
    fn test_decode_wrmsr() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x0F, 0x30, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Wrmsr);
        assert_eq!(decoded.size(), 2);
    }

    #[test]
    fn test_decode_rdmsr() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x0F, 0x32, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Rdmsr);
        assert_eq!(decoded.size(), 2);
    }

    #[test]
    fn test_decode_rdtsc() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x0F, 0x31, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Rdtsc);
        assert_eq!(decoded.size(), 2);
    }

    #[test]
    fn test_decode_rdtscp() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x0F, 0x01, 0xF9, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx).unwrap();
        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Rdtscp);
        assert_eq!(decoded.size(), 3);
    }

    #[test]
    fn test_decode_failed() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let err = insn.decode(&TestCtx);

        assert!(err.is_err());
    }
}
