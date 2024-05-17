// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

#![allow(dead_code)]

use super::insn::MAX_INSN_SIZE;
use super::InsnError;

/// Represents the raw bytes of an instruction and
/// tracks the number of bytes being processed.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct InsnBytes {
    /// Raw instruction bytes
    bytes: [u8; MAX_INSN_SIZE],
    /// Number of instruction bytes being processed
    nr_processed: usize,
}

impl InsnBytes {
    /// Creates a new `OpCodeBytes` instance with the provided instruction bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - An array of raw instruction bytes
    ///
    /// # Returns
    ///
    /// A new instance of `OpCodeBytes` with the `bytes` set to the provided
    /// array and the `nr_processed` field initialized to zero.
    pub const fn new(bytes: [u8; MAX_INSN_SIZE]) -> Self {
        Self {
            bytes,
            nr_processed: 0,
        }
    }

    /// Retrieves a single unprocessed instruction byte.
    ///
    /// # Returns
    ///
    /// An instruction byte if success or an [`InsnError`] otherwise.
    pub fn peek(&self) -> Result<u8, InsnError> {
        self.bytes
            .get(self.nr_processed)
            .copied()
            .ok_or(InsnError::InsnPeek)
    }

    /// Increases the count by one after a peeked byte being processed.
    pub fn advance(&mut self) {
        self.nr_processed += 1
    }

    /// Retrieves the number of processed instruction bytes.
    ///
    /// # Returns
    ///
    /// Returns the number of processed bytes as a `usize`.
    pub fn processed(&self) -> usize {
        self.nr_processed
    }
}

/// The instruction bytes specifically for OpCode decoding
#[derive(Clone, Copy, Debug)]
pub struct OpCodeBytes(pub InsnBytes);
