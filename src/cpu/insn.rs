// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Thomas Leroy <tleroy@suse.de>

extern crate alloc;

use crate::cpu::vc::VcError;
use crate::cpu::vc::VcErrorType;
use crate::error::SvsmError;
use core::ops::{Index, IndexMut};

pub const MAX_INSN_SIZE: usize = 15;
pub const MAX_INSN_FIELD_SIZE: usize = 3;

/// A common structure shared by different fields of an
/// [`Instruction`] struct.
#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub struct InsnBuffer<const N: usize>
where
    [u8; N]: Default,
{
    /// Internal buffer of constant size `N`.
    pub buf: [u8; N],
    /// Number of useful bytes to be taken from `buf`.
    /// if `nb_bytes = 0`, the corresponding structure has
    /// no useful information. Otherwise, only `self.buf[..self.nb_bytes]`
    /// is useful.
    pub nb_bytes: usize,
}

impl<const N: usize> InsnBuffer<N>
where
    [u8; N]: Default,
{
    fn new(buf: [u8; N], nb_bytes: usize) -> Self {
        Self { buf, nb_bytes }
    }
}

impl<const N: usize> Index<usize> for InsnBuffer<N>
where
    [u8; N]: Default,
{
    type Output = u8;
    fn index(&self, i: usize) -> &Self::Output {
        &self.buf[i]
    }
}

impl<const N: usize> IndexMut<usize> for InsnBuffer<N>
where
    [u8; N]: Default,
{
    fn index_mut(&mut self, i: usize) -> &mut Self::Output {
        &mut self.buf[i]
    }
}

/// A view of an x86 instruction.
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub struct Instruction {
    /// Optional x86 instruction prefixes.
    pub prefixes: Option<InsnBuffer<MAX_INSN_FIELD_SIZE>>,
    /// Raw bytes copied from rip location.
    /// After decoding, `self.insn_bytes.nb_bytes` is adjusted
    /// to the total len of the instruction, prefix included.
    pub insn_bytes: InsnBuffer<MAX_INSN_SIZE>,
    /// Mandatory opcode.
    pub opcode: InsnBuffer<MAX_INSN_FIELD_SIZE>,
    /// Operand size in bytes.
    pub opnd_bytes: usize,
}

impl Instruction {
    pub fn new(insn_bytes: [u8; MAX_INSN_SIZE]) -> Self {
        Self {
            prefixes: None,
            opcode: InsnBuffer::default(), // we'll copy content later
            insn_bytes: InsnBuffer::new(insn_bytes, 0),
            opnd_bytes: 4,
        }
    }

    /// Returns the length of the instruction.
    ///
    /// # Returns:
    ///
    /// [`usize`]: The total size of an  instruction,
    /// prefix included.
    pub fn len(&self) -> usize {
        self.insn_bytes.nb_bytes
    }

    /// Returns true if the related [`Instruction`] can be considered empty.
    pub fn is_empty(&self) -> bool {
        self.insn_bytes.nb_bytes == 0
    }

    /// Decode the instruction.
    /// At the moment, the decoding is very naive since we only need to decode CPUID,
    /// IN and OUT (without strings and immediate usage) instructions. A complete decoding
    /// of the full x86 instruction set is still TODO.
    ///
    /// # Returns
    ///
    /// [`Result<(), SvsmError>`]: A [`Result`] containing the empty
    /// value on success, or an [`SvsmError`] on failure.
    pub fn decode(&mut self) -> Result<(), SvsmError> {
        /*
         * At this point, we only need to handle IOIO (without string and immediate versions)
         * and CPUID, that both have a fixed size. No real complex x86 decoder is needed.
         */
        match self.insn_bytes[0] {
            // {in, out}w instructions uses a 0x66 operand-size opcode prefix
            0x66 => {
                if self.insn_bytes[1] == 0xED || self.insn_bytes[1] == 0xEF {
                    // for prefix length
                    self.prefixes = Some(InsnBuffer::new(
                        self.insn_bytes.buf[..MAX_INSN_FIELD_SIZE]
                            .try_into()
                            .unwrap(),
                        1,
                    ));

                    // for {in, out}w opcode length
                    self.opcode.nb_bytes = 1;
                    self.opcode[0] = self.insn_bytes[1];

                    self.insn_bytes.nb_bytes =
                        self.prefixes.unwrap().nb_bytes + self.opcode.nb_bytes;
                    self.opnd_bytes = 2;
                    return Ok(());
                }

                Err(SvsmError::Vc(VcError {
                    rip: 0,
                    code: 0,
                    error_type: VcErrorType::DecodeFailed,
                }))
            }
            // inb and oub register opcodes
            0xEC | 0xEE => {
                self.opcode.nb_bytes = 1;
                self.opcode[0] = self.insn_bytes[0];

                self.insn_bytes.nb_bytes = self.opcode.nb_bytes;
                self.opnd_bytes = 1;
                Ok(())
            }
            // inl and outl register opcodes
            0xED | 0xEF => {
                self.opcode.nb_bytes = 1;
                self.opcode[0] = self.insn_bytes[0];

                self.insn_bytes.nb_bytes = self.opcode.nb_bytes;
                self.opnd_bytes = 4;
                Ok(())
            }

            0x0F => {
                // CPUID opcode
                if self.insn_bytes[1] == 0xA2 {
                    self.opcode.nb_bytes = 2;
                    let opcode_len = self.opcode.nb_bytes;
                    self.opcode.buf[..opcode_len]
                        .clone_from_slice(&self.insn_bytes.buf[..opcode_len]);

                    self.insn_bytes.nb_bytes = self.opcode.nb_bytes;
                    return Ok(());
                }

                Err(SvsmError::Vc(VcError {
                    rip: 0,
                    code: 0,
                    error_type: VcErrorType::DecodeFailed,
                }))
            }
            _ => Err(SvsmError::Vc(VcError {
                rip: 0,
                code: 0,
                error_type: VcErrorType::DecodeFailed,
            })),
        }
    }
}

/// Copy the instruction bytes where rip points to.
///
/// # Arguments
///
/// rip: instruction pointer as [`*const u8`].
///
/// # Returns
///
/// [`[u8; MAX_INSN_SIZE]`]: the 15-byte buffer where rip points to.
///
/// # Safety
///
///  The caller should validate that `rip` is set to a valid address
///  and that the next [`MAX_INSN_SIZE`] bytes are within valid memory.
pub unsafe fn insn_fetch(rip: *const u8) -> [u8; MAX_INSN_SIZE] {
    rip.cast::<[u8; MAX_INSN_SIZE]>().read()
}

#[cfg(test)]
mod tests {
    use super::{InsnBuffer, Instruction, MAX_INSN_SIZE};

    #[test]
    fn test_decode_inw() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0xED, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut insn = Instruction::new(raw_insn);
        insn.decode().unwrap();

        let target = Instruction {
            prefixes: Some(InsnBuffer {
                buf: [0x66, 0xED, 0x41],
                nb_bytes: 1,
            }),
            insn_bytes: InsnBuffer {
                buf: raw_insn,
                nb_bytes: 2,
            },
            opcode: InsnBuffer {
                buf: [0xED, 0, 0],
                nb_bytes: 1,
            },
            opnd_bytes: 2,
        };

        assert_eq!(target, insn);
    }

    #[test]
    fn test_decode_outb() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xEE, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut insn = Instruction::new(raw_insn);
        insn.decode().unwrap();

        let target = Instruction {
            prefixes: None,
            insn_bytes: InsnBuffer {
                buf: raw_insn,
                nb_bytes: 1,
            },
            opcode: InsnBuffer {
                buf: [0xEE, 0, 0],
                nb_bytes: 1,
            },
            opnd_bytes: 1,
        };

        assert_eq!(target, insn);
    }

    #[test]
    fn test_decode_outl() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xEF, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut insn = Instruction::new(raw_insn);
        insn.decode().unwrap();

        let target = Instruction {
            prefixes: None,
            insn_bytes: InsnBuffer {
                buf: raw_insn,
                nb_bytes: 1,
            },
            opcode: InsnBuffer {
                buf: [0xEF, 0, 0],
                nb_bytes: 1,
            },
            opnd_bytes: 4,
        };

        assert_eq!(target, insn);
    }

    #[test]
    fn test_decode_cpuid() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x0F, 0xA2, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut insn = Instruction::new(raw_insn);
        insn.decode().unwrap();

        let target = Instruction {
            prefixes: None,
            insn_bytes: InsnBuffer {
                buf: raw_insn,
                nb_bytes: 2,
            },
            opcode: InsnBuffer {
                buf: [0x0F, 0xA2, 0],
                nb_bytes: 2,
            },
            opnd_bytes: 4,
        };

        assert_eq!(target, insn);
    }

    #[test]
    fn test_decode_failed() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0xEE, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut insn = Instruction::new(raw_insn);
        let err = insn.decode();

        assert!(err.is_err());
    }
}
