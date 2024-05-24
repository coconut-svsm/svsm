// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>
//
// The instruction decoding is implemented by refering instr_emul.c
// from the Arcn project, with some modifications. A copy of license
// is included below:
//
// Copyright (c) 2012 Sandvine, Inc.
// Copyright (c) 2012 NetApp, Inc.
// Copyright (c) 2017-2022 Intel Corporation.
//
// Aedistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//
// $FreeBSD$
//
// The original file can be found in this repository:
// https://github.com/projectacrn/acrn-hypervisor/blob/master/hypervisor/
// arch/x86/guest/instr_emul.c

use super::insn::{DecodedInsn, Immediate, Operand, MAX_INSN_SIZE};
use super::opcode::{OpCodeClass, OpCodeDesc, OpCodeFlags};
use super::{InsnError, Register, SegRegister};
use crate::cpu::control_regs::{CR0Flags, CR4Flags};
use crate::cpu::efer::EFERFlags;
use crate::cpu::registers::SegDescAttrFlags;
use crate::types::Bytes;
use bitflags::bitflags;

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

// The instruction bytes specifically for prefix decoding
#[derive(Clone, Copy, Debug)]
struct PrefixBytes(InsnBytes);
// The instruction bytes specifically for ModR/M decoding
#[derive(Clone, Copy, Debug)]
struct ModRmBytes(InsnBytes);
// The instruction bytes specifically for SIB decoding
#[derive(Clone, Copy, Debug)]
struct SibBytes(InsnBytes);
// The instruction bytes specifically for displacement decoding
#[derive(Clone, Copy, Debug)]
struct DisBytes(InsnBytes);
// The instruction bytes specifically for immediate decoding
#[derive(Clone, Copy, Debug)]
struct ImmBytes(InsnBytes);
// The instruction bytes specifically for Mem-Offset decoding
#[derive(Clone, Copy, Debug)]
struct MoffBytes(InsnBytes);
// The instruction bytes specifically after decoding completed
#[derive(Clone, Copy, Debug)]
struct DecodedBytes(InsnBytes);

/// This trait provides the necessary context for an instruction decoder
/// to decode instructions based on the current state of the machine
/// that executed them. It abstracts the interfaces through which an
/// instruction decoder can access specific registers and state that may
/// influence the decoding from the machine (such as a CPU or VMM).
pub trait InsnMachineCtx: core::fmt::Debug {
    /// Read EFER register
    fn read_efer(&self) -> u64;
    /// Read a code segment register
    fn read_seg(&self, seg: SegRegister) -> u64;
    /// Read CR0 register
    fn read_cr0(&self) -> u64;
    /// Read CR4 register
    fn read_cr4(&self) -> u64;
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum PagingLevel {
    Level4,
    Level5,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum CpuMode {
    #[default]
    Real,
    Protected,
    Compatibility,
    Bit64(PagingLevel),
}

impl CpuMode {
    fn is_bit64(&self) -> bool {
        matches!(self, CpuMode::Bit64(_))
    }
}

fn get_cpu_mode<I: InsnMachineCtx>(mctx: &I) -> CpuMode {
    if (mctx.read_efer() & EFERFlags::LMA.bits()) != 0 {
        // EFER.LMA = 1
        if (mctx.read_seg(SegRegister::CS) & SegDescAttrFlags::L.bits()) != 0 {
            // CS.L = 1 represents 64bit mode.
            // While this sub-mode produces 64-bit linear addresses, the processor
            // enforces canonicality, meaning that the upper bits of such an address
            // are identical: bits 63:47 for 4-level paging and bits 63:56 for
            // 5-level paging. 4-level paging (respectively, 5-level paging) does not
            // use bits 63:48 (respectively, bits 63:57) of such addresses
            let level = if (mctx.read_cr4() & CR4Flags::LA57.bits()) != 0 {
                PagingLevel::Level5
            } else {
                PagingLevel::Level4
            };
            CpuMode::Bit64(level)
        } else {
            CpuMode::Compatibility
        }
    } else if (mctx.read_cr0() & CR0Flags::PE.bits()) != 0 {
        // CR0.PE = 1
        CpuMode::Protected
    } else {
        CpuMode::Real
    }
}

// Translate the decoded number from the instruction ModR/M
// or SIB to the corresponding register
struct RegCode(u8);
impl TryFrom<RegCode> for Register {
    type Error = InsnError;

    fn try_from(val: RegCode) -> Result<Register, Self::Error> {
        match val.0 {
            0 => Ok(Register::Rax),
            1 => Ok(Register::Rcx),
            2 => Ok(Register::Rdx),
            3 => Ok(Register::Rbx),
            4 => Ok(Register::Rsp),
            5 => Ok(Register::Rbp),
            6 => Ok(Register::Rsi),
            7 => Ok(Register::Rdi),
            8 => Ok(Register::R8),
            9 => Ok(Register::R9),
            10 => Ok(Register::R10),
            11 => Ok(Register::R11),
            12 => Ok(Register::R12),
            13 => Ok(Register::R13),
            14 => Ok(Register::R14),
            15 => Ok(Register::R15),
            // Rip is not represented by ModR/M or SIB
            _ => Err(InsnError::InvalidRegister),
        }
    }
}

const PREFIX_SIZE: usize = 4;

bitflags! {
    #[derive(Copy, Clone, Debug, Default, PartialEq)]
    struct PrefixFlags: u16 {
        const REX_W                 = 1 << 0;
        const REX_R                 = 1 << 1;
        const REX_X                 = 1 << 2;
        const REX_B                 = 1 << 3;
        const REX_P                 = 1 << 4;
        const REPZ_P                = 1 << 5;
        const REPNZ_P               = 1 << 6;
        const OPSIZE_OVERRIDE       = 1 << 7;
        const ADDRSIZE_OVERRIDE     = 1 << 8;
    }
}

bitflags! {
    #[derive(Copy, Clone, Debug, Default, PartialEq)]
    struct RexPrefix: u8 {
        const B     = 1 << 0;
        const X     = 1 << 1;
        const R     = 1 << 2;
        const W     = 1 << 3;
    }
}

#[derive(Copy, Clone, Default, Debug, PartialEq)]
struct ModRM(u8);

const MOD_INDIRECT: u8 = 0;
const MOD_INDIRECT_DISP8: u8 = 1;
const MOD_INDIRECT_DISP32: u8 = 2;
const MOD_DIRECT: u8 = 3;
const RM_SIB: u8 = 4;
const RM_DISP32: u8 = 5;

impl From<u8> for ModRM {
    fn from(val: u8) -> Self {
        ModRM(val)
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum RM {
    Reg(Register),
    Sib,
    Disp32,
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum Mod {
    Indirect,
    IndirectDisp8,
    IndirectDisp32,
    Direct,
}

impl ModRM {
    fn get_mod(&self) -> Mod {
        let v = (self.0 >> 6) & 0x3;

        match v {
            MOD_INDIRECT => Mod::Indirect,
            MOD_INDIRECT_DISP8 => Mod::IndirectDisp8,
            MOD_INDIRECT_DISP32 => Mod::IndirectDisp32,
            MOD_DIRECT => Mod::Direct,
            _ => {
                unreachable!("Mod has only two bits, so its value is always 0 ~ 3");
            }
        }
    }

    fn get_reg(&self) -> u8 {
        (self.0 >> 3) & 0x7
    }

    fn get_rm(&self) -> RM {
        let rm = self.0 & 0x7;
        let r#mod = self.get_mod();

        // RM depends on the Mod value
        if r#mod == Mod::Indirect && rm == RM_DISP32 {
            RM::Disp32
        } else if r#mod != Mod::Direct && rm == RM_SIB {
            RM::Sib
        } else {
            RM::Reg(Register::try_from(RegCode(rm)).unwrap())
        }
    }
}

#[derive(Copy, Clone, Default, Debug, PartialEq)]
struct Sib(u8);

impl From<u8> for Sib {
    fn from(val: u8) -> Self {
        Sib(val)
    }
}

impl Sib {
    fn get_scale(&self) -> u8 {
        (self.0 >> 6) & 0x3
    }

    fn get_index(&self) -> u8 {
        (self.0 >> 3) & 0x7
    }

    fn get_base(&self) -> u8 {
        self.0 & 0x7
    }
}

/// Represents the context of a decoded instruction, which is used to
/// interpret the instruction. It holds the decoded instruction, its
/// length and various components that are decoded from the instruction
/// bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct DecodedInsnCtx {
    insn: Option<DecodedInsn>,
    insn_len: usize,
    cpu_mode: CpuMode,

    // Prefix
    prefix: PrefixFlags,
    override_seg: Option<SegRegister>,

    // Opcode description
    opdesc: Option<OpCodeDesc>,
    opsize: Bytes,
    addrsize: Bytes,

    // ModR/M byte
    modrm: ModRM,
    reg: u8,
    modrm_reg: Option<Register>,

    // SIB byte
    sib: Sib,
    scale: u8,
    index_reg: Option<Register>,
    base_reg: Option<Register>,

    // Optional addr displacement
    displacement: i64,

    // Optional immediate operand
    immediate: i64,
}

impl DecodedInsnCtx {
    /// Constructs a new `DecodedInsnCtx` by decoding the given
    /// instruction bytes using the provided machine context.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw bytes of the instruction to be decoded.
    /// * `mctx` - A reference to an object implementing the
    /// `InsnMachineCtx` trait to provide the necessary machine context
    /// for decoding.
    ///
    ///  # Returns
    ///
    ///  A `DecodedInsnCtx` if decoding is successful or an `InsnError`
    ///  otherwise.
    pub(super) fn new<I: InsnMachineCtx>(
        bytes: &[u8; MAX_INSN_SIZE],
        mctx: &I,
    ) -> Result<Self, InsnError> {
        let mut insn_ctx = Self {
            cpu_mode: get_cpu_mode(mctx),
            ..Default::default()
        };

        insn_ctx.decode(bytes, mctx).map(|_| insn_ctx)
    }

    /// Retrieves the decoded instruction, if available.
    ///
    /// # Returns
    ///
    /// An `Option<DecodedInsn>` containing the DecodedInsn.
    pub fn insn(&self) -> Option<DecodedInsn> {
        self.insn
    }

    /// Retrieves the length of the decoded instruction in bytes.
    ///
    /// # Returns
    ///
    /// The length of the decoded instruction as a `usize`.
    pub fn size(&self) -> usize {
        self.insn_len
    }

    fn decode<I: InsnMachineCtx>(
        &mut self,
        bytes: &[u8; MAX_INSN_SIZE],
        mctx: &I,
    ) -> Result<(), InsnError> {
        self.decode_prefixes(bytes, mctx)
            .and_then(|insn| self.decode_opcode(insn))
            .and_then(|insn| self.decode_modrm_sib(insn))
            .and_then(|(insn, disp_bytes)| self.decode_displacement(insn, disp_bytes))
            .and_then(|insn| self.decode_immediate(insn))
            .and_then(|insn| self.decode_moffset(insn))
            .and_then(|insn| self.complete_decode(insn))
    }

    #[inline]
    fn get_opdesc(&self) -> Result<OpCodeDesc, InsnError> {
        self.opdesc.ok_or(InsnError::NoOpCodeDesc)
    }

    fn decode_rex_prefix(&mut self, code: u8) -> bool {
        if !self.cpu_mode.is_bit64() {
            return false;
        }

        match code {
            0x40..=0x4F => {
                let rex = RexPrefix::from_bits_truncate(code);
                self.prefix.insert(PrefixFlags::REX_P);
                if rex.contains(RexPrefix::W) {
                    self.prefix.insert(PrefixFlags::REX_W);
                }
                if rex.contains(RexPrefix::R) {
                    self.prefix.insert(PrefixFlags::REX_R);
                }
                if rex.contains(RexPrefix::X) {
                    self.prefix.insert(PrefixFlags::REX_X);
                }
                if rex.contains(RexPrefix::B) {
                    self.prefix.insert(PrefixFlags::REX_B);
                }
                true
            }
            _ => false,
        }
    }

    fn decode_op_addr_size(&mut self, cs: u64) {
        (self.addrsize, self.opsize) = if self.cpu_mode.is_bit64() {
            (
                if self.prefix.contains(PrefixFlags::ADDRSIZE_OVERRIDE) {
                    Bytes::Four
                } else {
                    Bytes::Eight
                },
                if self.prefix.contains(PrefixFlags::REX_W) {
                    Bytes::Eight
                } else if self.prefix.contains(PrefixFlags::OPSIZE_OVERRIDE) {
                    Bytes::Two
                } else {
                    Bytes::Four
                },
            )
        } else if (cs & SegDescAttrFlags::DB.bits()) != 0 {
            // Default address and operand sizes are 32-bits
            (
                if self.prefix.contains(PrefixFlags::ADDRSIZE_OVERRIDE) {
                    Bytes::Two
                } else {
                    Bytes::Four
                },
                if self.prefix.contains(PrefixFlags::OPSIZE_OVERRIDE) {
                    Bytes::Two
                } else {
                    Bytes::Four
                },
            )
        } else {
            // Default address and operand sizes are 16-bits
            (
                if self.prefix.contains(PrefixFlags::ADDRSIZE_OVERRIDE) {
                    Bytes::Four
                } else {
                    Bytes::Two
                },
                if self.prefix.contains(PrefixFlags::OPSIZE_OVERRIDE) {
                    Bytes::Four
                } else {
                    Bytes::Two
                },
            )
        };
    }

    fn decode_prefixes<I: InsnMachineCtx>(
        &mut self,
        bytes: &[u8; MAX_INSN_SIZE],
        mctx: &I,
    ) -> Result<OpCodeBytes, InsnError> {
        let mut insn = PrefixBytes(InsnBytes::new(*bytes));
        for _ in 0..PREFIX_SIZE {
            match insn.0.peek()? {
                0x66 => self.prefix.insert(PrefixFlags::OPSIZE_OVERRIDE),
                0x67 => self.prefix.insert(PrefixFlags::ADDRSIZE_OVERRIDE),
                0xF3 => self.prefix.insert(PrefixFlags::REPZ_P),
                0xF2 => self.prefix.insert(PrefixFlags::REPNZ_P),
                0x2E => self.override_seg = Some(SegRegister::CS),
                0x36 => self.override_seg = Some(SegRegister::SS),
                0x3E => self.override_seg = Some(SegRegister::DS),
                0x26 => self.override_seg = Some(SegRegister::ES),
                0x64 => self.override_seg = Some(SegRegister::FS),
                0x65 => self.override_seg = Some(SegRegister::GS),
                _ => break,
            }
            insn.0.advance();
        }

        // From section 2.2.1, "REX Prefixes", Intel SDM Vol 2:
        // - Only one REX prefix is allowed per instruction.
        // - The REX prefix must immediately precede the opcode byte or the
        //   escape opcode byte.
        // - If an instruction has a mandatory prefix (0x66, 0xF2 or 0xF3)
        //   the mandatory prefix must come before the REX prefix.
        if self.decode_rex_prefix(insn.0.peek()?) {
            insn.0.advance();
        }

        self.decode_op_addr_size(mctx.read_seg(SegRegister::CS));

        Ok(OpCodeBytes(insn.0))
    }

    fn decode_opcode(&mut self, mut insn: OpCodeBytes) -> Result<ModRmBytes, InsnError> {
        let opdesc = OpCodeDesc::decode(&mut insn).ok_or(InsnError::DecodeOpCode)?;

        if opdesc.flags.contains(OpCodeFlags::BYTE_OP) {
            self.opsize = Bytes::One;
        } else if opdesc.flags.contains(OpCodeFlags::WORD_OP) {
            self.opsize = Bytes::Two;
        }

        self.opdesc = Some(opdesc);

        Ok(ModRmBytes(insn.0))
    }

    fn decode_modrm_sib(&mut self, mut insn: ModRmBytes) -> Result<(DisBytes, Bytes), InsnError> {
        if self.get_opdesc()?.flags.contains(OpCodeFlags::NO_MODRM) {
            return Ok((DisBytes(insn.0), Bytes::Zero));
        }

        if self.cpu_mode == CpuMode::Real {
            return Err(InsnError::DecodeModRM);
        }

        self.modrm = ModRM::from(insn.0.peek()?);

        if self.get_opdesc()?.flags.contains(OpCodeFlags::OP_NONE) {
            insn.0.advance();
            return Ok((DisBytes(insn.0), Bytes::Zero));
        }

        let r#mod = self.modrm.get_mod();
        self.reg = self.modrm.get_reg() | ((self.prefix.contains(PrefixFlags::REX_R) as u8) << 3);
        self.modrm_reg = Some(Register::try_from(RegCode(self.reg))?);

        // As the modrm decoding is majorly for MMIO instructions which requires
        // a memory access, a direct addressing mode makes no sense in the context.
        // There has to be a memory access involved to trap the MMIO instruction.
        if r#mod == Mod::Direct {
            return Err(InsnError::DecodeModRM);
        }

        // SDM Vol2 Table 2-5: Special Cases of REX Encodings
        // For mod=0 r/m=5 and mod!=3 r/m=4, the 'b' bit in the REX
        // prefix is 'don't care' in these two cases.
        //
        // RM::Disp32 represent mod=0 r/m=5
        // RM::Sib represent mod!=3 r/m=4
        // RM::Reg(r) represent the other cases.
        let disp_bytes = match self.modrm.get_rm() {
            RM::Reg(r) => {
                let ext_r = Register::try_from(RegCode(
                    r as u8 | ((self.prefix.contains(PrefixFlags::REX_B) as u8) << 3),
                ))?;
                self.base_reg = Some(ext_r);
                match r#mod {
                    Mod::IndirectDisp8 => Bytes::One,
                    Mod::IndirectDisp32 => Bytes::Four,
                    Mod::Indirect | Mod::Direct => Bytes::Zero,
                }
            }
            RM::Disp32 => {
                // SDM Vol2 Table 2-7: RIP-Relative Addressing
                // In 64bit mode, mod=0 r/m=5 implies [rip] + disp32
                // whereas in compatibility mode it just implies disp32.
                self.base_reg = if self.cpu_mode.is_bit64() {
                    Some(Register::Rip)
                } else {
                    None
                };
                Bytes::Four
            }
            RM::Sib => {
                insn.0.advance();
                return self.decode_sib(SibBytes(insn.0));
            }
        };

        insn.0.advance();
        Ok((DisBytes(insn.0), disp_bytes))
    }

    fn decode_sib(&mut self, mut insn: SibBytes) -> Result<(DisBytes, Bytes), InsnError> {
        // Process only if SIB byte is present
        if self.modrm.get_rm() != RM::Sib {
            return Err(InsnError::DecodeSib);
        }

        self.sib = Sib::from(insn.0.peek()?);
        let index = self.sib.get_index() | ((self.prefix.contains(PrefixFlags::REX_X) as u8) << 3);
        let base = self.sib.get_base() | ((self.prefix.contains(PrefixFlags::REX_B) as u8) << 3);

        let r#mod = self.modrm.get_mod();
        let disp_bytes = match r#mod {
            Mod::IndirectDisp8 => {
                self.base_reg = Some(Register::try_from(RegCode(base))?);
                Bytes::One
            }
            Mod::IndirectDisp32 => {
                self.base_reg = Some(Register::try_from(RegCode(base))?);
                Bytes::Four
            }
            Mod::Indirect => {
                let mut disp_bytes = Bytes::Zero;
                // SMD Vol 2 Table 2-5 Special Cases of REX Encoding
                // Base register is unused if mod=0 base=RBP/R13.
                self.base_reg = if base == Register::Rbp as u8 || base == Register::R13 as u8 {
                    disp_bytes = Bytes::Four;
                    None
                } else {
                    Some(Register::try_from(RegCode(base))?)
                };
                disp_bytes
            }
            Mod::Direct => Bytes::Zero,
        };

        // SMD Vol 2 Table 2-5 Special Cases of REX Encoding
        // Index register not used when index=RSP
        if index != Register::Rsp as u8 {
            self.index_reg = Some(Register::try_from(RegCode(index))?);
            // 'scale' makes sense only in the context of an index register
            self.scale = 1 << self.sib.get_scale();
        }

        insn.0.advance();
        Ok((DisBytes(insn.0), disp_bytes))
    }

    fn decode_displacement(
        &mut self,
        mut insn: DisBytes,
        disp_bytes: Bytes,
    ) -> Result<ImmBytes, InsnError> {
        match disp_bytes {
            Bytes::Zero => Ok(ImmBytes(insn.0)),
            Bytes::One | Bytes::Four => {
                let mut buf = [0; 4];

                for v in buf.iter_mut().take(disp_bytes as usize) {
                    *v = insn.0.peek()?;
                    insn.0.advance();
                }

                self.displacement = if disp_bytes == Bytes::One {
                    buf[0] as i8 as i64
                } else {
                    i32::from_le_bytes(buf) as i64
                };

                Ok(ImmBytes(insn.0))
            }
            _ => Err(InsnError::DecodeDisp),
        }
    }

    fn decode_immediate(&mut self, mut insn: ImmBytes) -> Result<MoffBytes, InsnError> {
        // Figure out immediate operand size (if any)
        let imm_bytes = if self.get_opdesc()?.flags.contains(OpCodeFlags::IMM) {
            match self.opsize {
                // SDM Vol 2 2.2.1.5 "Immediates"
                // In 64-bit mode the typical size of immediate operands
                // remains 32-bits. When the operand size if 64-bits, the
                // processor sign-extends all immediates to 64-bits prior
                // to their use.
                Bytes::Four | Bytes::Eight => Bytes::Four,
                _ => Bytes::Two,
            }
        } else if self.get_opdesc()?.flags.contains(OpCodeFlags::IMM8) {
            Bytes::One
        } else {
            // No flags on immediate operand size
            return Ok(MoffBytes(insn.0));
        };

        let mut buf = [0; 4];

        for v in buf.iter_mut().take(imm_bytes as usize) {
            *v = insn.0.peek()?;
            insn.0.advance();
        }

        self.immediate = match imm_bytes {
            Bytes::One => buf[0] as i8 as i64,
            Bytes::Two => i16::from_le_bytes([buf[0], buf[1]]) as i64,
            Bytes::Four => i32::from_le_bytes(buf) as i64,
            _ => return Err(InsnError::DecodeImm),
        };

        Ok(MoffBytes(insn.0))
    }

    fn decode_moffset(&mut self, mut insn: MoffBytes) -> Result<DecodedBytes, InsnError> {
        if !self.get_opdesc()?.flags.contains(OpCodeFlags::MOFFSET) {
            return Ok(DecodedBytes(insn.0));
        }

        match self.addrsize {
            Bytes::Zero | Bytes::One => Err(InsnError::DecodeMOffset),
            _ => {
                // SDM Vol 2 Section 2.2.1.4, "Direct Memory-Offset MOVs"
                // In 64-bit mode, direct memory-offset forms of the MOV
                // instruction are extended to specify a 64-bit immediate
                // absolute address.
                //
                // The memory offset size follows the address-size of the instruction.
                let mut buf = [0; 8];
                for v in buf.iter_mut().take(self.addrsize as usize) {
                    *v = insn.0.peek()?;
                    insn.0.advance();
                }
                self.displacement = i64::from_le_bytes(buf);
                Ok(DecodedBytes(insn.0))
            }
        }
    }

    fn complete_decode(&mut self, insn: DecodedBytes) -> Result<(), InsnError> {
        self.insn_len = insn.0.processed();
        self.decoded_insn()
            .map(|decoded_insn| self.insn = Some(decoded_insn))
    }

    fn decoded_insn(&self) -> Result<DecodedInsn, InsnError> {
        let opdesc = self.get_opdesc()?;
        Ok(match opdesc.class {
            OpCodeClass::Cpuid => DecodedInsn::Cpuid,
            OpCodeClass::In => {
                let operand = if opdesc.flags.contains(OpCodeFlags::IMM8) {
                    Operand::Imm(Immediate::U8(self.immediate as u8))
                } else {
                    Operand::rdx()
                };
                match self.opsize {
                    Bytes::One => DecodedInsn::Inb(operand),
                    Bytes::Two => DecodedInsn::Inw(operand),
                    Bytes::Four => DecodedInsn::Inl(operand),
                    _ => return Err(InsnError::UnSupportedInsn),
                }
            }
            OpCodeClass::Out => {
                let operand = if opdesc.flags.contains(OpCodeFlags::IMM8) {
                    Operand::Imm(Immediate::U8(self.immediate as u8))
                } else {
                    Operand::rdx()
                };
                match self.opsize {
                    Bytes::One => DecodedInsn::Outb(operand),
                    Bytes::Two => DecodedInsn::Outw(operand),
                    Bytes::Four => DecodedInsn::Outl(operand),
                    _ => return Err(InsnError::UnSupportedInsn),
                }
            }
            OpCodeClass::Rdmsr => DecodedInsn::Rdmsr,
            OpCodeClass::Rdtsc => DecodedInsn::Rdtsc,
            OpCodeClass::Rdtscp => DecodedInsn::Rdtscp,
            OpCodeClass::Wrmsr => DecodedInsn::Wrmsr,
            _ => return Err(InsnError::UnSupportedInsn),
        })
    }
}
