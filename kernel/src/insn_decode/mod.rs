// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

mod decode;
mod insn;
mod opcode;

pub use decode::{DecodedInsnCtx, InsnMachineCtx, InsnMachineMem};
#[cfg(any(test, fuzzing))]
pub use insn::test_utils::TestCtx;
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
    /// Error due to alignment check exception.
    ExceptionAC,
    /// Error due to general protection exception.
    ExceptionGP(u8),
    /// Error due to page fault exception.
    ExceptionPF(usize, u32),
    /// Error due to stack segment exception.
    ExceptionSS,
    /// Error while mapping linear addresses.
    MapLinearAddr,
    /// Error while reading from memory.
    MemRead,
    /// Error while writing to memory.
    MemWrite,
    /// No OpCodeDesc generated while decoding.
    NoOpCodeDesc,
    /// Error while peeking an instruction byte.
    InsnPeek,
    /// The instruction decoding is not invalid.
    InvalidDecode,
    /// Invalid RegCode for decoding Register.
    InvalidRegister,
    /// Error while handling input IO operation.
    IoIoIn,
    /// Error while handling output IO operation.
    IoIoOut,
    /// The decoded instruction is not supported.
    UnSupportedInsn,
    /// Error while translating linear address.
    TranslateLinearAddr,
    /// Error while handling MMIO read operation.
    HandleMmioRead,
    /// Error while handling MMIO write operation.
    HandleMmioWrite,
}

impl From<InsnError> for crate::error::SvsmError {
    fn from(e: InsnError) -> Self {
        Self::Insn(e)
    }
}
