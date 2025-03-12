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

extern crate alloc;

use super::insn::{DecodedInsn, Immediate, Operand, MAX_INSN_SIZE};
use super::opcode::{OpCodeClass, OpCodeDesc, OpCodeFlags};
use super::{InsnError, Register, SegRegister};
use crate::cpu::control_regs::{CR0Flags, CR4Flags};
use crate::cpu::efer::EFERFlags;
use crate::cpu::registers::{RFlags, SegDescAttrFlags};
use crate::types::Bytes;
use alloc::boxed::Box;
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

    /// Read a register
    fn read_reg(&self, _reg: Register) -> usize {
        unimplemented!("Reading register is not implemented");
    }

    /// Read rflags register
    fn read_flags(&self) -> usize {
        unimplemented!("Reading flags is not implemented");
    }

    /// Write a register
    fn write_reg(&mut self, _reg: Register, _val: usize) {
        unimplemented!("Writing register is not implemented");
    }

    /// Read the current privilege level
    fn read_cpl(&self) -> usize {
        unimplemented!("Reading CPL is not implemented");
    }

    /// Map the given linear address region to a machine memory object
    /// which provides access to the memory of this linear address region.
    ///
    /// # Arguments
    ///
    /// * `la` - The linear address of the region to map.
    /// * `write` - Whether write access is allowed to the mapped region.
    /// * `fetch` - Whether fetch access is allowed to the mapped region.
    ///
    /// # Returns
    ///
    /// A `Result` containing a boxed trait object representing the mapped
    /// memory, or an `InsnError` if mapping fails.
    fn map_linear_addr<T: Copy + 'static>(
        &self,
        _la: usize,
        _write: bool,
        _fetch: bool,
    ) -> Result<Box<dyn InsnMachineMem<Item = T>>, InsnError> {
        Err(InsnError::MapLinearAddr)
    }

    /// Check IO permission bitmap.
    ///
    /// # Arguments
    ///
    /// * `port` - The I/O port to check.
    /// * `size` - The size of the I/O operation.
    /// * `io_read` - Whether the I/O operation is a read operation.
    ///
    /// # Returns
    ///
    /// A `Result` containing true if the port is permitted otherwise false.
    fn ioio_perm(&self, _port: u16, _size: Bytes, _io_read: bool) -> bool {
        unimplemented!("Checking IO permission bitmap is not implemented");
    }

    /// Handle an I/O in operation.
    ///
    /// # Arguments
    ///
    /// * `port` - The I/O port to read from.
    /// * `size` - The size of the data to read.
    ///
    /// # Returns
    ///
    /// A `Result` containing the read data if success or an `InsnError` if
    /// the operation fails.
    fn ioio_in(&self, _port: u16, _size: Bytes) -> Result<u64, InsnError> {
        Err(InsnError::IoIoIn)
    }

    /// Handle an I/O out operation.
    ///
    /// # Arguments
    ///
    /// * `port` - The I/O port to write to.
    /// * `size` - The size of the data to write.
    /// * `data` - The data to write to the I/O port.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an `InsnError` if the operation fails.
    fn ioio_out(&mut self, _port: u16, _size: Bytes, _data: u64) -> Result<(), InsnError> {
        Err(InsnError::IoIoOut)
    }

    /// Translate the given linear address to a physical address.
    ///
    /// # Arguments
    ///
    /// * `la` - The linear address to translate.
    /// * `write` - Whether the translation is for a write operation.
    /// * `fetch` - Whether the translation is for a fetch operation.
    ///
    /// # Returns
    ///
    /// A `Result` containing the translated physical address and a boolean
    /// indicating whether the physical address is shared or an `InsnError` if
    /// the translation fails.
    fn translate_linear_addr(
        &self,
        _la: usize,
        _write: bool,
        _fetch: bool,
    ) -> Result<(usize, bool), InsnError> {
        Err(InsnError::TranslateLinearAddr)
    }

    /// Handle a memory-mapped I/O read operation.
    ///
    /// # Arguments
    ///
    /// * `pa` - The MMIO physical address to read from.
    /// * `shared` - Whether the MMIO address is shared.
    /// * `size` - The size of the data to read.
    ///
    /// # Returns
    ///
    /// A `Result` containing the read data if success or an `InsnError` if
    /// the operation fails.
    fn handle_mmio_read(&self, _pa: usize, _shared: bool, _size: Bytes) -> Result<u64, InsnError> {
        Err(InsnError::HandleMmioRead)
    }

    /// Handle a memory-mapped I/O write operation.
    ///
    /// # Arguments
    ///
    /// * `pa` - The MMIO physical address to write to.
    /// * `shared` - Whether the MMIO address is shared.
    /// * `size` - The size of the data to write.
    /// * `data` - The data to write to the MMIO.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or an `InsnError` if the operation fails.
    fn handle_mmio_write(
        &mut self,
        _pa: usize,
        _shared: bool,
        _size: Bytes,
        _data: u64,
    ) -> Result<(), InsnError> {
        Err(InsnError::HandleMmioWrite)
    }
}

/// Trait representing a machine memory for instruction decoding.
pub trait InsnMachineMem {
    type Item;

    /// Read data from the memory at the specified offset.
    ///
    /// # Safety
    ///
    /// The caller must verify not to read data from arbitrary memory. The object implements this
    /// trait should guarantee the memory region is readable.
    ///
    /// # Returns
    ///
    /// Returns the read data on success, or an `InsnError` if the read
    /// operation fails.
    unsafe fn mem_read(&self) -> Result<Self::Item, InsnError> {
        Err(InsnError::MemRead)
    }

    /// Write data to the memory at the specified offset.
    ///
    /// # Safety
    ///
    /// The caller must verify not to write data to corrupt arbitrary memory. The object implements
    /// this trait should guarantee the memory region is writable.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to write to the memory.
    ///
    /// # Returns
    ///
    /// Returns `Ok`on success, or an `InsnError` if the write operation fails.
    unsafe fn mem_write(&mut self, _data: Self::Item) -> Result<(), InsnError> {
        Err(InsnError::MemWrite)
    }
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

#[inline]
fn read_reg<I: InsnMachineCtx>(mctx: &I, reg: Register, size: Bytes) -> usize {
    mctx.read_reg(reg) & size.mask() as usize
}

#[inline]
fn write_reg<I: InsnMachineCtx>(mctx: &mut I, reg: Register, data: usize, size: Bytes) {
    mctx.write_reg(
        reg,
        match size {
            Bytes::Zero => return,
            // Writing 8bit or 16bit register will not affect the upper bits.
            Bytes::One | Bytes::Two => {
                let old = mctx.read_reg(reg);
                (data & size.mask() as usize) | (old & !size.mask() as usize)
            }
            // Writing 32bit register will zero out the upper bits.
            Bytes::Four => data & size.mask() as usize,
            Bytes::Eight => data,
        },
    );
}

#[inline]
fn segment_base(segment: u64) -> u32 {
    // Segment base bits 0 ~ 23: raw value bits 16 ~ 39
    // Segment base bits 24 ~ 31: raw value bits 56 ~ 63
    (((segment >> 16) & 0xffffff) | ((segment >> 56) << 24)) as u32
}

#[inline]
fn segment_limit(segment: u64) -> u32 {
    // Segment limit bits 0 ~ 15: raw value bits 0 ~ 15
    // Segment limit bits 16 ~ 19: raw value bits 48 ~ 51
    let limit = ((segment & 0xffff) | ((segment >> 32) & 0xf0000)) as u32;

    if SegDescAttrFlags::from_bits_truncate(segment).contains(SegDescAttrFlags::G) {
        (limit << 12) | 0xfff
    } else {
        limit
    }
}

fn ioio_perm<I: InsnMachineCtx>(mctx: &I, port: u16, size: Bytes, io_read: bool) -> bool {
    if mctx.read_cr0() & CR0Flags::PE.bits() != 0
        && (mctx.read_cpl() > ((mctx.read_flags() >> 12) & 3)
            || mctx.read_cr4() & CR4Flags::VME.bits() != 0)
    {
        // In protected mode with CPL > IOPL or virtual-8086 mode, if
        // any I/O Permission Bit for I/O port being accessed = 1, the I/O
        // operation is not allowed.
        mctx.ioio_perm(port, size, io_read)
    } else {
        true
    }
}

#[inline]
fn read_bytereg<I: InsnMachineCtx>(mctx: &I, reg: Register, lhbr: bool) -> u8 {
    let data = mctx.read_reg(reg);
    // To obtain the value of a legacy high byte register shift the
    // base register right by 8 bits (%ah = %rax >> 8).
    (if lhbr { data >> 8 } else { data }) as u8
}

#[inline]
fn write_bytereg<I: InsnMachineCtx>(mctx: &mut I, reg: Register, lhbr: bool, data: u8) {
    let old = mctx.read_reg(reg);
    let mask = (Bytes::One).mask() as usize;

    let new = if lhbr {
        (data as usize) << 8 | (old & !(mask << 8))
    } else {
        (data as usize) | (old & !mask)
    };

    mctx.write_reg(reg, new);
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

    // Instruction repeat count
    repeat: usize,
}

impl DecodedInsnCtx {
    /// Constructs a new `DecodedInsnCtx` by decoding the given
    /// instruction bytes using the provided machine context.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw bytes of the instruction to be decoded.
    /// * `mctx` - A reference to an object implementing the
    ///   `InsnMachineCtx` trait to provide the necessary machine context
    ///   for decoding.
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
    /// The length of the decoded instruction as a `usize`. If the
    /// repeat count is greater than 1, then return 0 to indicate not to
    /// skip this instruction. If the repeat count is less than 1, then
    /// return instruction len to indicate this instruction can be skipped.
    pub fn size(&self) -> usize {
        if self.repeat > 1 {
            0
        } else {
            self.insn_len
        }
    }

    /// Emulates the decoded instruction using the provided machine context.
    ///
    /// # Arguments
    ///
    /// * `mctx` - A mutable reference to an object implementing the
    ///   `InsnMachineCtx` trait to provide the necessary machine context
    ///   for emulation.
    ///
    /// # Returns
    ///
    /// An `Ok(())` if emulation is successful or an `InsnError` otherwise.
    pub fn emulate<I: InsnMachineCtx>(&self, mctx: &mut I) -> Result<(), InsnError> {
        self.insn
            .ok_or(InsnError::UnSupportedInsn)
            .and_then(|insn| match insn {
                DecodedInsn::In(port, opsize) => self.emulate_in_out(port, opsize, mctx, true),
                DecodedInsn::Out(port, opsize) => self.emulate_in_out(port, opsize, mctx, false),
                DecodedInsn::Ins => self.emulate_ins_outs(mctx, true),
                DecodedInsn::Outs => self.emulate_ins_outs(mctx, false),
                DecodedInsn::Mov => self.emulate_mov(mctx),
                _ => Err(InsnError::UnSupportedInsn),
            })
    }

    /// Emulates IOIO instructions using the provided machine context.
    ///
    /// # Arguments
    ///
    /// * `mctx` - A mutable reference to an object implementing the
    ///   `InsnMachineCtx` trait to provide the necessary machine context
    ///   for emulation.
    ///
    /// # Returns
    ///
    /// An `Ok(())` if emulation is successful or an `InsnError` otherwise.
    pub fn emulate_ioio<I: InsnMachineCtx>(&self, mctx: &mut I) -> Result<(), InsnError> {
        self.insn
            .ok_or(InsnError::UnSupportedInsn)
            .and_then(|insn| match insn {
                DecodedInsn::In(_, _)
                | DecodedInsn::Out(_, _)
                | DecodedInsn::Ins
                | DecodedInsn::Outs => self.emulate(mctx),
                _ => Err(InsnError::UnSupportedInsn),
            })
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
            .and_then(|insn| self.complete_decode(insn, mctx))
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
        let reg = self.modrm.get_reg() | ((self.prefix.contains(PrefixFlags::REX_R) as u8) << 3);
        self.modrm_reg = Some(Register::try_from(RegCode(reg))?);

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

    fn complete_decode<I: InsnMachineCtx>(
        &mut self,
        insn: DecodedBytes,
        mctx: &I,
    ) -> Result<(), InsnError> {
        self.insn_len = insn.0.processed();
        self.decoded_insn(mctx)
            .map(|decoded_insn| self.insn = Some(decoded_insn))
    }

    fn decoded_insn<I: InsnMachineCtx>(&mut self, mctx: &I) -> Result<DecodedInsn, InsnError> {
        let opdesc = self.get_opdesc()?;
        Ok(match opdesc.class {
            OpCodeClass::Cpuid => DecodedInsn::Cpuid,
            OpCodeClass::In => {
                if opdesc.flags.contains(OpCodeFlags::IMM8) {
                    DecodedInsn::In(
                        Operand::Imm(Immediate::U8(self.immediate as u8)),
                        self.opsize,
                    )
                } else {
                    DecodedInsn::In(Operand::rdx(), self.opsize)
                }
            }
            OpCodeClass::Out => {
                if opdesc.flags.contains(OpCodeFlags::IMM8) {
                    DecodedInsn::Out(
                        Operand::Imm(Immediate::U8(self.immediate as u8)),
                        self.opsize,
                    )
                } else {
                    DecodedInsn::Out(Operand::rdx(), self.opsize)
                }
            }
            OpCodeClass::Ins | OpCodeClass::Outs => {
                if self.prefix.contains(PrefixFlags::REPZ_P) {
                    // The prefix REPZ(F3h) actually represents REP for ins/outs.
                    // The count register is depending on the address size of the
                    // instruction.
                    self.repeat = read_reg(mctx, Register::Rcx, self.addrsize);
                };

                if opdesc.class == OpCodeClass::Ins {
                    DecodedInsn::Ins
                } else {
                    DecodedInsn::Outs
                }
            }
            OpCodeClass::Rdmsr => DecodedInsn::Rdmsr,
            OpCodeClass::Rdtsc => DecodedInsn::Rdtsc,
            OpCodeClass::Rdtscp => DecodedInsn::Rdtscp,
            OpCodeClass::Wrmsr => DecodedInsn::Wrmsr,
            OpCodeClass::Mov => DecodedInsn::Mov,
            _ => return Err(InsnError::UnSupportedInsn),
        })
    }

    #[inline]
    fn get_modrm_reg(&self) -> Result<Register, InsnError> {
        self.modrm_reg.ok_or(InsnError::InvalidDecode)
    }

    fn cal_modrm_bytereg(&self) -> Result<(Register, bool), InsnError> {
        let reg = self.get_modrm_reg()?;
        // 64-bit mode imposes limitations on accessing legacy high byte
        // registers (lhbr).
        //
        // The legacy high-byte registers cannot be addressed if the REX
        // prefix is present. In this case the values 4, 5, 6 and 7 of the
        // 'ModRM:reg' field address %spl, %bpl, %sil and %dil respectively.
        //
        // If the REX prefix is not present then the values 4, 5, 6 and 7
        // of the 'ModRM:reg' field address the legacy high-byte registers,
        // %ah, %ch, %dh and %bh respectively.
        Ok(
            if !self.prefix.contains(PrefixFlags::REX_P) && (reg as u8 & 0x4) != 0 {
                (Register::try_from(RegCode(reg as u8 & 0x3))?, true)
            } else {
                (reg, false)
            },
        )
    }

    fn canonical_check(&self, la: usize) -> Option<usize> {
        if match self.cpu_mode {
            CpuMode::Bit64(level) => {
                let virtaddr_bits = if level == PagingLevel::Level4 { 48 } else { 57 };
                let mask = !((1 << virtaddr_bits) - 1);
                if la & (1 << (virtaddr_bits - 1)) != 0 {
                    la & mask == mask
                } else {
                    la & mask == 0
                }
            }
            _ => true,
        } {
            Some(la)
        } else {
            None
        }
    }

    fn alignment_check(&self, la: usize, size: Bytes) -> Option<usize> {
        match size {
            // Zero size is not allowed
            Bytes::Zero => None,
            // One byte is always aligned
            Bytes::One => Some(la),
            // Two/Four/Eight bytes must be aligned on a boundary
            _ => {
                if la & (size as usize - 1) != 0 {
                    None
                } else {
                    Some(la)
                }
            }
        }
    }

    fn cal_linear_addr<I: InsnMachineCtx>(
        &self,
        mctx: &I,
        seg: SegRegister,
        ea: usize,
        writable: bool,
    ) -> Option<usize> {
        let segment = mctx.read_seg(seg);

        let addrsize = if self.cpu_mode.is_bit64() {
            Bytes::Eight
        } else {
            let attr = SegDescAttrFlags::from_bits_truncate(segment);
            // Invalid if is system segment
            if !attr.contains(SegDescAttrFlags::S) {
                return None;
            }

            if writable {
                // Writing to a code segment, or writing to a read-only
                // data segment is not allowed.
                if attr.contains(SegDescAttrFlags::C_D) || !attr.contains(SegDescAttrFlags::R_W) {
                    return None;
                }
            } else {
                // Data segment is always read-able, but code segment
                // may be execute only. Invalid if read an execute only
                // code segment.
                if attr.contains(SegDescAttrFlags::C_D) && !attr.contains(SegDescAttrFlags::R_W) {
                    return None;
                }
            }

            let mut limit = segment_limit(segment) as usize;

            if !attr.contains(SegDescAttrFlags::C_D) && attr.contains(SegDescAttrFlags::C_E) {
                // Expand-down segment, check low limit
                if ea <= limit {
                    return None;
                }

                limit = if attr.contains(SegDescAttrFlags::DB) {
                    u32::MAX as usize
                } else {
                    u16::MAX as usize
                }
            }

            // Check high limit for each byte
            for i in 0..self.opsize as usize {
                if ea + i > limit {
                    return None;
                }
            }

            Bytes::Four
        };

        self.canonical_check(
            if self.cpu_mode.is_bit64() && seg != SegRegister::FS && seg != SegRegister::GS {
                ea & (addrsize.mask() as usize)
            } else {
                (segment_base(segment) as usize + ea) & addrsize.mask() as usize
            },
        )
    }

    fn get_linear_addr<I: InsnMachineCtx>(
        &self,
        mctx: &I,
        seg: SegRegister,
        ea: usize,
        writable: bool,
    ) -> Result<usize, InsnError> {
        self.cal_linear_addr(mctx, seg, ea, writable)
            .ok_or(if seg == SegRegister::SS {
                InsnError::ExceptionSS
            } else {
                InsnError::ExceptionGP(0)
            })
            .and_then(|la| {
                if (mctx.read_cpl() == 3)
                    && (mctx.read_cr0() & CR0Flags::AM.bits()) != 0
                    && (mctx.read_flags() & RFlags::AC.bits()) != 0
                {
                    self.alignment_check(la, self.opsize)
                        .ok_or(InsnError::ExceptionAC)
                } else {
                    Ok(la)
                }
            })
    }

    fn emulate_ins_outs<I: InsnMachineCtx>(
        &self,
        mctx: &mut I,
        io_read: bool,
    ) -> Result<(), InsnError> {
        // I/O port number is stored in DX.
        let port = mctx.read_reg(Register::Rdx) as u16;

        // Check the IO permission bit map.
        if !ioio_perm(mctx, port, self.opsize, io_read) {
            return Err(InsnError::ExceptionGP(0));
        }

        let (seg, reg) = if io_read {
            // Input byte from I/O port specified in DX into
            // memory location specified with ES:(E)DI or
            // RDI.
            (SegRegister::ES, Register::Rdi)
        } else {
            // Output byte/word/doubleword from memory location specified in
            // DS:(E)SI (The DS segment may be overridden with a segment
            // override prefix.) or RSI to I/O port specified in DX.
            (
                self.override_seg.map_or(SegRegister::DS, |s| s),
                Register::Rsi,
            )
        };

        // Decoed the linear addresses and map as a memory object
        // which allows accessing to the memory represented by the
        // linear addresses.
        let linear_addr =
            self.get_linear_addr(mctx, seg, read_reg(mctx, reg, self.addrsize), io_read)?;
        if io_read {
            // Read data from IO port and then write to the memory location.
            let data = mctx.ioio_in(port, self.opsize)?;
            // Safety: The linear address is decoded from the instruction and checked. It can be
            // remapped to a memory object with the write permission successfully, and the remapped
            // memory size matches the operand size of the instruction.
            unsafe {
                match self.opsize {
                    Bytes::One => mctx
                        .map_linear_addr::<u8>(linear_addr, io_read, false)?
                        .mem_write(data as u8)?,
                    Bytes::Two => mctx
                        .map_linear_addr::<u16>(linear_addr, io_read, false)?
                        .mem_write(data as u16)?,
                    Bytes::Four => mctx
                        .map_linear_addr::<u32>(linear_addr, io_read, false)?
                        .mem_write(data as u32)?,
                    _ => return Err(InsnError::IoIoIn),
                };
            }
        } else {
            // Read data from memory location and then write to the IO port
            //
            // Safety: The linear address is decoded from the instruction and checked. It can be
            // remapped to a memory object with the read permission successfully, and the remapped
            // memory size matches the operand size of the instruction.
            let data = unsafe {
                match self.opsize {
                    Bytes::One => mctx
                        .map_linear_addr::<u8>(linear_addr, io_read, false)?
                        .mem_read()? as u64,
                    Bytes::Two => mctx
                        .map_linear_addr::<u16>(linear_addr, io_read, false)?
                        .mem_read()? as u64,
                    Bytes::Four => mctx
                        .map_linear_addr::<u32>(linear_addr, io_read, false)?
                        .mem_read()? as u64,
                    _ => return Err(InsnError::IoIoOut),
                }
            };
            mctx.ioio_out(port, self.opsize, data)?;
        }

        let rflags = RFlags::from_bits_truncate(mctx.read_flags());
        if rflags.contains(RFlags::DF) {
            // The DF flag is 1, the (E)SI/DI register is decremented.
            write_reg(
                mctx,
                reg,
                read_reg(mctx, reg, self.addrsize)
                    .checked_sub(self.opsize as usize)
                    .ok_or(InsnError::IoIoOut)?,
                self.addrsize,
            );
        } else {
            // The DF flag is 0, the (E)SI/DI register is incremented.
            write_reg(
                mctx,
                reg,
                read_reg(mctx, reg, self.addrsize)
                    .checked_add(self.opsize as usize)
                    .ok_or(InsnError::IoIoOut)?,
                self.addrsize,
            );
        }

        if self.repeat != 0 {
            // Update the count register with the left count which are not
            // emulated yet.
            write_reg(mctx, Register::Rcx, self.repeat - 1, self.addrsize);
        }

        Ok(())
    }

    fn emulate_in_out<I: InsnMachineCtx>(
        &self,
        port: Operand,
        opsize: Bytes,
        mctx: &mut I,
        io_read: bool,
    ) -> Result<(), InsnError> {
        let port = match port {
            Operand::Reg(Register::Rdx) => mctx.read_reg(Register::Rdx) as u16,
            Operand::Reg(..) => unreachable!("Port value is always in DX"),
            Operand::Imm(imm) => match imm {
                Immediate::U8(val) => val as u16,
                _ => unreachable!("Port value in immediate is always 1 byte"),
            },
        };

        // Check the IO permission bit map
        if !ioio_perm(mctx, port, opsize, io_read) {
            return Err(InsnError::ExceptionGP(0));
        }

        if io_read {
            // Read data from IO port and then write to AL/AX/EAX.
            write_reg(
                mctx,
                Register::Rax,
                mctx.ioio_in(port, opsize)? as usize,
                opsize,
            );
        } else {
            // Read data from AL/AX/EAX and then write to the IO port.
            mctx.ioio_out(port, opsize, read_reg(mctx, Register::Rax, opsize) as u64)?;
        }

        Ok(())
    }

    fn cal_effective_addr<I: InsnMachineCtx>(&self, mctx: &I) -> Result<usize, InsnError> {
        let base = if let Some(reg) = self.base_reg {
            match reg {
                Register::Rip => {
                    // RIP relative addressing is used in 64bit mode and
                    // starts from the following instruction
                    mctx.read_reg(reg) + self.insn_len
                }
                _ => mctx.read_reg(reg),
            }
        } else {
            0
        };

        let index = if let Some(reg) = self.index_reg {
            mctx.read_reg(reg)
        } else {
            0
        };

        Ok(base
            .checked_add(index << (self.scale as usize))
            .and_then(|v| v.checked_add(self.displacement as usize))
            .ok_or(InsnError::InvalidDecode)?
            & self.addrsize.mask() as usize)
    }

    #[inline]
    fn emulate_mmio_read<I: InsnMachineCtx>(
        &self,
        mctx: &I,
        seg: SegRegister,
        ea: usize,
    ) -> Result<u64, InsnError> {
        mctx.translate_linear_addr(self.get_linear_addr(mctx, seg, ea, false)?, false, false)
            .and_then(|(addr, shared)| mctx.handle_mmio_read(addr, shared, self.opsize))
    }

    #[inline]
    fn emulate_mmio_write<I: InsnMachineCtx>(
        &self,
        mctx: &mut I,
        seg: SegRegister,
        ea: usize,
        data: u64,
    ) -> Result<(), InsnError> {
        mctx.translate_linear_addr(self.get_linear_addr(mctx, seg, ea, true)?, true, false)
            .and_then(|(addr, shared)| mctx.handle_mmio_write(addr, shared, self.opsize, data))
    }

    fn emulate_mov<I: InsnMachineCtx>(&self, mctx: &mut I) -> Result<(), InsnError> {
        if self.prefix.contains(PrefixFlags::REPZ_P) {
            return Err(InsnError::UnSupportedInsn);
        }

        let seg = if let Some(s) = self.override_seg {
            s
        } else if self.base_reg == Some(Register::Rsp) || self.base_reg == Some(Register::Rbp) {
            SegRegister::SS
        } else {
            SegRegister::DS
        };
        let ea = self.cal_effective_addr(mctx)?;

        match self.get_opdesc()?.code {
            0x88 => {
                // Mov byte from reg (ModRM:reg) to mem (ModRM:r/m)
                // 88/r:	mov r/m8, r8
                // REX + 88/r:	mov r/m8, r8 (%ah, %ch, %dh, %bh not available)
                let (reg, lhbr) = self.cal_modrm_bytereg()?;
                let data = read_bytereg(mctx, reg, lhbr);
                self.emulate_mmio_write(mctx, seg, ea, data as u64)?;
            }
            0x89 => {
                // MOV from reg (ModRM:reg) to mem (ModRM:r/m)
                // 89/r:	mov r/m16, r16
                // 89/r:	mov r/m32, r32
                // REX.W + 89/r	mov r/m64, r64
                let data = read_reg(mctx, self.get_modrm_reg()?, self.opsize);
                self.emulate_mmio_write(mctx, seg, ea, data as u64)?;
            }
            0x8A => {
                // MOV byte from mem (ModRM:r/m) to reg (ModRM:reg)
                // 8A/r:	mov r8, r/m8
                // REX + 8A/r:	mov r8, r/m8
                let data = self.emulate_mmio_read(mctx, seg, ea)?;
                let (reg, lhbr) = self.cal_modrm_bytereg()?;
                write_bytereg(mctx, reg, lhbr, data as u8);
            }
            0x8B => {
                // MOV from mem (ModRM:r/m) to reg (ModRM:reg)
                // 8B/r:	mov r16, r/m16
                // 8B/r:	mov r32, r/m32
                // REX.W 8B/r:	mov r64, r/m64
                let data = self.emulate_mmio_read(mctx, seg, ea)?;
                write_reg(mctx, self.get_modrm_reg()?, data as usize, self.opsize);
            }
            0xA1 => {
                // MOV from seg:moffset to AX/EAX/RAX
                // A1:		mov AX, moffs16
                // A1:		mov EAX, moffs32
                // REX.W + A1:	mov RAX, moffs64
                let data = self.emulate_mmio_read(mctx, seg, ea)?;
                write_reg(mctx, Register::Rax, data as usize, self.opsize);
            }
            0xA3 => {
                // MOV from AX/EAX/RAX to seg:moffset
                // A3:		mov moffs16, AX
                // A3:		mov moffs32, EAX
                // REX.W + A3:	mov moffs64, RAX
                let data = read_reg(mctx, Register::Rax, self.opsize);
                self.emulate_mmio_write(mctx, seg, ea, data as u64)?;
            }
            0xC6 | 0xC7 => {
                // MOV from imm8 to mem (ModRM:r/m)
                // C6/0		mov r/m8, imm8
                // REX + C6/0	mov r/m8, imm8
                // MOV from imm16/imm32 to mem (ModRM:r/m)
                // C7/0		mov r/m16, imm16
                // C7/0		mov r/m32, imm32
                // REX.W + C7/0	mov r/m64, imm32 (sign-extended to 64-bits)
                self.emulate_mmio_write(mctx, seg, ea, self.immediate as u64 & self.opsize.mask())?;
            }
            _ => return Err(InsnError::UnSupportedInsn),
        }

        Ok(())
    }
}
