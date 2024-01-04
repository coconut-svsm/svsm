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

#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub struct InsnBuffer<const N: usize>
where
    [u8; N]: Default,
{
    pub buf: [u8; N],
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

#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub struct Instruction {
    pub prefixes: InsnBuffer<MAX_INSN_FIELD_SIZE>,
    pub insn_bytes: InsnBuffer<MAX_INSN_SIZE>,
    pub opcode: InsnBuffer<MAX_INSN_FIELD_SIZE>,
    pub opnd_bytes: usize,
}

impl Instruction {
    pub fn new(insn_bytes: [u8; MAX_INSN_SIZE]) -> Self {
        Self {
            prefixes: InsnBuffer::new(insn_bytes[..MAX_INSN_FIELD_SIZE].try_into().unwrap(), 0),
            opcode: InsnBuffer::default(), // we'll copy content later
            insn_bytes: InsnBuffer::new(insn_bytes, 0),
            opnd_bytes: 4,
        }
    }

    pub fn len(&self) -> usize {
        self.insn_bytes.nb_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.insn_bytes.nb_bytes == 0
    }

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
                    self.prefixes.nb_bytes = 1;

                    // for {in, out}w opcode length
                    self.opcode.nb_bytes = 1;
                    self.opcode[0] = self.insn_bytes[1];

                    self.insn_bytes.nb_bytes = self.prefixes.nb_bytes + self.opcode.nb_bytes;
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
                self.prefixes.nb_bytes = 0;

                self.opcode.nb_bytes = 1;
                self.opcode[0] = self.insn_bytes[0];

                self.insn_bytes.nb_bytes = self.opcode.nb_bytes;
                self.opnd_bytes = 1;
                Ok(())
            }
            // inl and outl register opcodes
            0xED | 0xEF => {
                self.prefixes.nb_bytes = 0;

                self.opcode.nb_bytes = 1;
                self.opcode[0] = self.insn_bytes[0];

                self.insn_bytes.nb_bytes = self.opcode.nb_bytes;
                self.opnd_bytes = 4;
                Ok(())
            }

            0x0F => {
                // CPUID opcode
                if self.insn_bytes[1] == 0xA2 {
                    self.prefixes.nb_bytes = 0;

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
            prefixes: InsnBuffer {
                buf: [0x66, 0xED, 0x41],
                nb_bytes: 1,
            },
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
            prefixes: InsnBuffer {
                buf: [0xEE, 0x41, 0x41],
                nb_bytes: 0,
            },
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
            prefixes: InsnBuffer {
                buf: [0xEF, 0x41, 0x41],
                nb_bytes: 0,
            },
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
            prefixes: InsnBuffer {
                buf: [0x0F, 0xA2, 0x41],
                nb_bytes: 0,
            },
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
