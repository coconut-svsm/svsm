// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Thomas Leroy <tleroy@suse.de>

extern crate alloc;

use crate::cpu::vc::VcError;
use crate::cpu::vc::VcErrorType;
use crate::error::SvsmError;

pub const MAX_INSN_SIZE: usize = 15;
pub const MAX_INSN_FIELD_SIZE: usize = 3;

#[derive(Default, Debug, Copy, Clone)]
pub struct Instruction {
    pub prefixes: InstructionField,
    pub insn_bytes: [u8; MAX_INSN_SIZE],
    pub length: usize,
    pub opcode: InstructionField,
    pub opnd_bytes: usize,
}

#[derive(Default, Debug, Copy, Clone)]
pub struct InstructionField {
    pub bytes: [u8; MAX_INSN_FIELD_SIZE],
    pub nb_bytes: usize,
}

impl Instruction {
    pub fn new(insn_bytes: [u8; MAX_INSN_SIZE]) -> Self {
        Self {
            prefixes: InstructionField {
                bytes: insn_bytes[..MAX_INSN_FIELD_SIZE].try_into().unwrap(),
                nb_bytes: 0,
            },
            insn_bytes,
            length: 0,
            opcode: InstructionField::default(), // we'll copy content later
            opnd_bytes: 4,
        }
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
                    self.prefixes.nb_bytes = 1;

                    self.opcode.nb_bytes = 1;
                    self.opcode.bytes[0] = self.insn_bytes[1];

                    self.length = self.prefixes.nb_bytes + self.opcode.nb_bytes;
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
                self.opcode.bytes[0] = self.insn_bytes[0];

                self.length = self.opcode.nb_bytes;
                self.opnd_bytes = 1;
                Ok(())
            }
            // inl and outl register opcodes
            0xED | 0xEF => {
                self.prefixes.nb_bytes = 0;

                self.opcode.nb_bytes = 1;
                self.opcode.bytes[0] = self.insn_bytes[0];

                self.length = self.opcode.nb_bytes;
                self.opnd_bytes = 4;
                Ok(())
            }

            0x0F => {
                // CPUID opcode
                if self.insn_bytes[1] == 0xA2 {
                    self.prefixes.nb_bytes = 0;

                    self.opcode.nb_bytes = 2;
                    self.opcode.bytes[..2].clone_from_slice(&self.insn_bytes[..2]);

                    self.length = self.opcode.nb_bytes;
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
