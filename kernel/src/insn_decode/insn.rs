// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Thomas Leroy <tleroy@suse.de>

use crate::cpu::vc::VcError;
use crate::cpu::vc::VcErrorType;
use crate::error::SvsmError;

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
    Rbx,
    Rcx,
    Rdx,
    Rsp,
    Rbp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

/// An operand in an instruction, which might be a register or an immediate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operand {
    Reg(Register),
    Imm(Immediate),
}

impl Operand {
    #[inline]
    const fn rdx() -> Self {
        Self::Reg(Register::Rdx)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedInsn {
    Cpuid,
    Inl(Operand),
    Inb(Operand),
    Inw(Operand),
    Outl(Operand),
    Outb(Operand),
    Outw(Operand),
    Wrmsr,
    Rdmsr,
    Rdtsc,
    Rdtscp,
}

impl DecodedInsn {
    pub const fn size(&self) -> usize {
        match self {
            Self::Cpuid => 2,
            Self::Inb(Operand::Reg(..)) => 1,
            Self::Inw(Operand::Reg(..)) => 2,
            Self::Inl(Operand::Reg(..)) => 1,
            Self::Outb(Operand::Reg(..)) => 1,
            Self::Outw(Operand::Reg(..)) => 2,
            Self::Outl(Operand::Reg(..)) => 1,
            Self::Inb(Operand::Imm(..)) => 2,
            Self::Inw(Operand::Imm(..)) => 3,
            Self::Inl(Operand::Imm(..)) => 2,
            Self::Outb(Operand::Imm(..)) => 2,
            Self::Outw(Operand::Imm(..)) => 3,
            Self::Outl(Operand::Imm(..)) => 2,
            Self::Wrmsr | Self::Rdmsr => 2,
            Self::Rdtsc => 2,
            Self::Rdtscp => 3,
        }
    }
}

pub const MAX_INSN_SIZE: usize = 15;

/// A view of an x86 instruction.
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub struct Instruction([u8; MAX_INSN_SIZE]);

impl Instruction {
    pub const fn new(bytes: [u8; MAX_INSN_SIZE]) -> Self {
        Self(bytes)
    }

    /// Decode the instruction.
    /// At the moment, the decoding is very naive since we only need to decode CPUID,
    /// IN and OUT (without strings and immediate usage) instructions. A complete decoding
    /// of the full x86 instruction set is still TODO.
    ///
    /// # Returns
    ///
    /// A [`DecodedInsn`] if the instruction is supported, or an [`SvsmError`] otherwise.
    pub fn decode(&self) -> Result<DecodedInsn, SvsmError> {
        match self.0[0] {
            0xE4 => return Ok(DecodedInsn::Inb(Operand::Imm(Immediate::U8(self.0[1])))),
            0xE5 => return Ok(DecodedInsn::Inl(Operand::Imm(Immediate::U8(self.0[1])))),
            0xE6 => return Ok(DecodedInsn::Outb(Operand::Imm(Immediate::U8(self.0[1])))),
            0xE7 => return Ok(DecodedInsn::Outl(Operand::Imm(Immediate::U8(self.0[1])))),
            0xEC => return Ok(DecodedInsn::Inb(Operand::rdx())),
            0xED => return Ok(DecodedInsn::Inl(Operand::rdx())),
            0xEE => return Ok(DecodedInsn::Outb(Operand::rdx())),
            0xEF => return Ok(DecodedInsn::Outl(Operand::rdx())),
            0x66 => match self.0[1] {
                0xE5 => return Ok(DecodedInsn::Inw(Operand::Imm(Immediate::U8(self.0[2])))),
                0xE7 => return Ok(DecodedInsn::Outw(Operand::Imm(Immediate::U8(self.0[2])))),
                0xED => return Ok(DecodedInsn::Inw(Operand::rdx())),
                0xEF => return Ok(DecodedInsn::Outw(Operand::rdx())),
                _ => (),
            },
            0x0F => match self.0[1] {
                0x01 => {
                    if self.0[2] == 0xf9 {
                        return Ok(DecodedInsn::Rdtscp);
                    }
                }
                0x30 => return Ok(DecodedInsn::Wrmsr),
                0x31 => return Ok(DecodedInsn::Rdtsc),
                0x32 => return Ok(DecodedInsn::Rdmsr),
                0xA2 => return Ok(DecodedInsn::Cpuid),
                _ => (),
            },
            _ => (),
        }

        Err(VcError {
            rip: 0,
            code: 0,
            error_type: VcErrorType::DecodeFailed,
        }
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_inw() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0xED, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode().unwrap();
        assert_eq!(decoded, DecodedInsn::Inw(Operand::rdx()));
        assert_eq!(decoded.size(), 2);
    }

    #[test]
    fn test_decode_outb() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xEE, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode().unwrap();
        assert_eq!(decoded, DecodedInsn::Outb(Operand::rdx()));
        assert_eq!(decoded.size(), 1);
    }

    #[test]
    fn test_decode_outl() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xEF, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode().unwrap();
        assert_eq!(decoded, DecodedInsn::Outl(Operand::rdx()));
        assert_eq!(decoded.size(), 1);
    }

    #[test]
    fn test_decode_cpuid() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x0F, 0xA2, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode().unwrap();
        assert_eq!(decoded, DecodedInsn::Cpuid);
        assert_eq!(decoded.size(), 2);
    }

    #[test]
    fn test_decode_failed() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0xEE, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let err = insn.decode();

        assert!(err.is_err());
    }
}
