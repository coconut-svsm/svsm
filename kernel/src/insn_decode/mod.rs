// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

mod decode;
mod insn;
mod opcode;

pub use insn::{
    DecodedInsn, Immediate, Instruction, Operand, Register, SegRegister, MAX_INSN_SIZE,
};

/// An error that can occur during instruction decoding.
#[derive(Copy, Clone, Debug)]
pub enum InsnError {
    /// Error while decoding the displacement bytes.
    DecodeDisp,
    /// Error while decoding the immediate bytes.
    DecodeImm,
    /// Error while decoding the Mem-Offset bytes.
    DecodeMOffset,
    /// Error while decoding the ModR/M byte.
    DecodeModRM,
    /// Error while decoding the OpCode bytes.
    DecodeOpCode,
    /// Error while decoding the prefix bytes.
    DecodePrefix,
    /// Error while decoding the SIB byte.
    DecodeSib,
    /// No OpCodeDesc generated while decoding.
    NoOpCodeDesc,
    /// Error while peeking an instruction byte.
    InsnPeek,
    /// Invalid RegCode for decoding Register.
    InvalidRegister,
    /// The decoded instruction is not supported.
    UnSupportedInsn,
}
