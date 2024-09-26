// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::decode::OpCodeBytes;
use bitflags::bitflags;

bitflags! {
    /// Defines a set of flags for opcode attributes. These flags provide
    /// information about the characteristics of an opcode, such as the
    /// presence of an immediate operand, operand size, and special decoding
    /// requirements.
    #[derive(Clone, Copy, Debug, Default, PartialEq)]
    pub struct OpCodeFlags: u64 {
        // Immediate operand with decoded size
        const IMM           = 1 << 0;
        // U8 immediate operand
        const IMM8          = 1 << 1;
        // No need to decode ModRm
        const NO_MODRM      = 1 << 2;
        // Operand size is one byte
        const BYTE_OP       = 1 << 3;
        // Operand size is two byte
        const WORD_OP       = 1 << 4;
        // Doesn't have an operand
        const OP_NONE       = 1 << 5;
        // Need to decode Moffset
        const MOFFSET       = 1 << 6;
    }
}

/// Represents the classification of opcodes into distinct categories.
/// Each variant of the enum corresponds to a specific type of opcode
/// or a group of opcodes that share common characteristics or decoding
/// behaviors.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OpCodeClass {
    Cpuid,
    Group7,
    Group7Rm7,
    In,
    Ins,
    Mov,
    Out,
    Outs,
    Rdmsr,
    Rdtsc,
    Rdtscp,
    TwoByte,
    Wrmsr,
}

/// Descriptor for an opcode, which contains the raw instruction opcode
/// value, its corresponding class and flags for fully decoding the
/// instruction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OpCodeDesc {
    /// The opcode value
    pub code: u8,
    /// The type of the opcode
    pub class: OpCodeClass,
    /// The flags for fully decoding the instruction
    pub flags: OpCodeFlags,
}

macro_rules! opcode {
    ($class:expr) => {
        Some(OpCodeDesc {
            code: 0,
            class: $class,
            flags: OpCodeFlags::empty(),
        })
    };
    ($code:expr, $class:expr) => {
        Some(OpCodeDesc {
            code: $code,
            class: $class,
            flags: OpCodeFlags::empty(),
        })
    };
    ($code:expr, $class:expr, $flags:expr) => {
        Some(OpCodeDesc {
            code: $code,
            class: $class,
            flags: OpCodeFlags::from_bits_truncate($flags),
        })
    };
}

static ONE_BYTE_TABLE: [Option<OpCodeDesc>; 256] = {
    let mut table: [Option<OpCodeDesc>; 256] = [None; 256];

    table[0x0F] = opcode!(OpCodeClass::TwoByte);
    table[0x6C] = opcode!(
        0x6C,
        OpCodeClass::Ins,
        OpCodeFlags::BYTE_OP.bits() | OpCodeFlags::NO_MODRM.bits()
    );
    table[0x6D] = opcode!(0x6D, OpCodeClass::Ins, OpCodeFlags::NO_MODRM.bits());
    table[0x6E] = opcode!(
        0x6E,
        OpCodeClass::Outs,
        OpCodeFlags::BYTE_OP.bits() | OpCodeFlags::NO_MODRM.bits()
    );
    table[0x6F] = opcode!(0x6F, OpCodeClass::Outs, OpCodeFlags::NO_MODRM.bits());
    table[0x88] = opcode!(0x88, OpCodeClass::Mov, OpCodeFlags::BYTE_OP.bits());
    table[0x8A] = opcode!(0x8A, OpCodeClass::Mov, OpCodeFlags::BYTE_OP.bits());
    table[0x89] = opcode!(0x89, OpCodeClass::Mov);
    table[0x8B] = opcode!(0x8B, OpCodeClass::Mov);
    table[0xA1] = opcode!(
        0xA1,
        OpCodeClass::Mov,
        OpCodeFlags::MOFFSET.bits() | OpCodeFlags::NO_MODRM.bits()
    );
    table[0xA3] = opcode!(
        0xA3,
        OpCodeClass::Mov,
        OpCodeFlags::MOFFSET.bits() | OpCodeFlags::NO_MODRM.bits()
    );
    table[0xC6] = opcode!(
        0xC6,
        OpCodeClass::Mov,
        OpCodeFlags::BYTE_OP.bits() | OpCodeFlags::IMM8.bits()
    );
    table[0xC7] = opcode!(0xC7, OpCodeClass::Mov, OpCodeFlags::IMM.bits());
    table[0xE4] = opcode!(
        0xE4,
        OpCodeClass::In,
        OpCodeFlags::IMM8.bits() | OpCodeFlags::BYTE_OP.bits() | OpCodeFlags::NO_MODRM.bits()
    );
    table[0xE5] = opcode!(
        0xE5,
        OpCodeClass::In,
        OpCodeFlags::IMM8.bits() | OpCodeFlags::NO_MODRM.bits()
    );
    table[0xE6] = opcode!(
        0xE6,
        OpCodeClass::Out,
        OpCodeFlags::IMM8.bits() | OpCodeFlags::BYTE_OP.bits() | OpCodeFlags::NO_MODRM.bits()
    );
    table[0xE7] = opcode!(
        0xE7,
        OpCodeClass::Out,
        OpCodeFlags::IMM8.bits() | OpCodeFlags::NO_MODRM.bits()
    );
    table[0xEC] = opcode!(
        0xEC,
        OpCodeClass::In,
        OpCodeFlags::BYTE_OP.bits() | OpCodeFlags::NO_MODRM.bits()
    );
    table[0xED] = opcode!(0xED, OpCodeClass::In, OpCodeFlags::NO_MODRM.bits());
    table[0xEE] = opcode!(
        0xEE,
        OpCodeClass::Out,
        OpCodeFlags::BYTE_OP.bits() | OpCodeFlags::NO_MODRM.bits()
    );
    table[0xEF] = opcode!(0xEF, OpCodeClass::Out, OpCodeFlags::NO_MODRM.bits());

    table
};

static GROUP7_RM7_TABLE: [Option<OpCodeDesc>; 8] = {
    let mut table = [None; 8];

    table[1] = opcode!(0xF9, OpCodeClass::Rdtscp, OpCodeFlags::OP_NONE.bits());

    table
};

static GROUP7_TABLE: [Option<OpCodeDesc>; 16] = {
    let mut table = [None; 16];

    table[15] = opcode!(OpCodeClass::Group7Rm7);

    table
};

static TWO_BYTE_TABLE: [Option<OpCodeDesc>; 256] = {
    let mut table = [None; 256];

    table[0x01] = opcode!(OpCodeClass::Group7);
    table[0x30] = opcode!(0x30, OpCodeClass::Wrmsr, OpCodeFlags::NO_MODRM.bits());
    table[0x31] = opcode!(0x31, OpCodeClass::Rdtsc, OpCodeFlags::NO_MODRM.bits());
    table[0x32] = opcode!(0x32, OpCodeClass::Rdmsr, OpCodeFlags::NO_MODRM.bits());
    table[0xA2] = opcode!(0xA2, OpCodeClass::Cpuid, OpCodeFlags::NO_MODRM.bits());

    table
};

impl OpCodeDesc {
    fn one_byte(insn: &mut OpCodeBytes) -> Option<OpCodeDesc> {
        if let Ok(byte) = insn.0.peek() {
            // Advance the OpCodeBytes as this is a opcode byte
            insn.0.advance();
            ONE_BYTE_TABLE.get(byte as usize).cloned().flatten()
        } else {
            None
        }
    }

    fn two_byte(insn: &mut OpCodeBytes) -> Option<OpCodeDesc> {
        if let Ok(byte) = insn.0.peek() {
            // Advance the OpCodeBytes as this is a opcode byte
            insn.0.advance();
            TWO_BYTE_TABLE.get(byte as usize).cloned().flatten()
        } else {
            None
        }
    }

    fn group7(insn: &OpCodeBytes) -> Option<OpCodeDesc> {
        if let Ok(modrm) = insn.0.peek() {
            // Not to advance the OpCodeBytes as this is not a opcode byte
            let r#mod = modrm >> 6;
            let offset = (modrm >> 3) & 0x7;
            let idx = if r#mod == 3 { 8 + offset } else { offset };
            GROUP7_TABLE.get(idx as usize).cloned().flatten()
        } else {
            None
        }
    }

    fn group7_rm7(insn: &OpCodeBytes) -> Option<OpCodeDesc> {
        if let Ok(modrm) = insn.0.peek() {
            // Not to advance the OpCodeBytes as this is not a opcode byte
            let idx = modrm & 0x7;
            GROUP7_RM7_TABLE.get(idx as usize).cloned().flatten()
        } else {
            None
        }
    }

    /// Decodes an opcode from the given `OpCodeBytes`.
    ///
    /// # Arguments
    ///
    /// * `insn` - A mutable reference to the `OpCodeBytes` representing
    ///   the bytes of the opcode to be decoded.
    ///
    /// # Returns
    ///
    /// A Some(OpCodeDesc) if the opcode is supported or None otherwise
    pub fn decode(insn: &mut OpCodeBytes) -> Option<OpCodeDesc> {
        let mut opdesc = Self::one_byte(insn);

        loop {
            if let Some(desc) = opdesc {
                opdesc = match desc.class {
                    OpCodeClass::TwoByte => Self::two_byte(insn),
                    OpCodeClass::Group7 => Self::group7(insn),
                    OpCodeClass::Group7Rm7 => Self::group7_rm7(insn),
                    _ => return opdesc,
                }
            } else {
                return None;
            }
        }
    }
}
