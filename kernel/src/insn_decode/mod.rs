// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

mod decode;
mod insn;
mod opcode;

pub use insn::{DecodedInsn, Immediate, Instruction, Operand, Register, MAX_INSN_SIZE};

/// An error that can occur during instruction decoding.
#[derive(Copy, Clone, Debug)]
pub enum InsnError {
    /// Error while peeking an instruction byte.
    InsnPeek,
}
