// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Thomas Leroy <tleroy@suse.de>

use super::decode::DecodedInsnCtx;
use super::{InsnError, InsnMachineCtx};
use crate::types::Bytes;

/// An immediate value in an instruction
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Immediate {
    U8(u8),
    U16(u16),
    U32(u32),
}

/// A register in an instruction
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Register {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
}

/// A Segment register in instruction
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SegRegister {
    CS,
    SS,
    DS,
    ES,
    FS,
    GS,
}

/// An operand in an instruction, which might be a register or an immediate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operand {
    Reg(Register),
    Imm(Immediate),
}

impl Operand {
    #[inline]
    pub const fn rdx() -> Self {
        Self::Reg(Register::Rdx)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodedInsn {
    Cpuid,
    In(Operand, Bytes),
    Ins,
    Mov,
    Out(Operand, Bytes),
    Outs,
    Wrmsr,
    Rdmsr,
    Rdtsc,
    Rdtscp,
}

pub const MAX_INSN_SIZE: usize = 15;

/// A view of an x86 instruction.
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub struct Instruction([u8; MAX_INSN_SIZE]);

impl Instruction {
    pub const fn new(bytes: [u8; MAX_INSN_SIZE]) -> Self {
        Self(bytes)
    }

    /// Decode the instruction with the given InsnMachineCtx.
    ///
    /// # Returns
    ///
    /// A [`DecodedInsnCtx`] if the instruction is supported, or an [`InsnError`] otherwise.
    pub fn decode<I: InsnMachineCtx>(&self, mctx: &I) -> Result<DecodedInsnCtx, InsnError> {
        DecodedInsnCtx::new(&self.0, mctx)
    }
}

#[cfg(any(test, fuzzing))]
pub mod test_utils {
    extern crate alloc;

    use crate::cpu::control_regs::{CR0Flags, CR4Flags};
    use crate::cpu::efer::EFERFlags;
    use crate::insn_decode::*;
    use crate::types::Bytes;
    use alloc::boxed::Box;

    pub const TEST_PORT: u16 = 0xE0;

    /// A dummy struct to implement InsnMachineCtx for testing purposes.
    #[derive(Copy, Clone, Debug)]
    pub struct TestCtx {
        pub efer: u64,
        pub cr0: u64,
        pub cr4: u64,

        pub rax: usize,
        pub rdx: usize,
        pub rcx: usize,
        pub rbx: usize,
        pub rsp: usize,
        pub rbp: usize,
        pub rdi: usize,
        pub rsi: usize,
        pub r8: usize,
        pub r9: usize,
        pub r10: usize,
        pub r11: usize,
        pub r12: usize,
        pub r13: usize,
        pub r14: usize,
        pub r15: usize,
        pub rip: usize,
        pub flags: usize,

        pub ioport: u16,
        pub iodata: u64,

        pub mmio_reg: u64,
    }

    impl Default for TestCtx {
        fn default() -> Self {
            Self {
                efer: EFERFlags::LMA.bits(),
                cr0: CR0Flags::PE.bits(),
                cr4: CR4Flags::LA57.bits(),
                rax: 0,
                rdx: 0,
                rcx: 0,
                rbx: 0,
                rsp: 0,
                rbp: 0,
                rdi: 0,
                rsi: 0,
                r8: 0,
                r9: 0,
                r10: 0,
                r11: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
                rip: 0,
                flags: 0,
                ioport: TEST_PORT,
                iodata: u64::MAX,
                mmio_reg: 0,
            }
        }
    }

    #[cfg_attr(not(test), expect(dead_code))]
    struct TestMem<T: Copy> {
        ptr: *mut T,
    }

    impl InsnMachineCtx for TestCtx {
        fn read_efer(&self) -> u64 {
            self.efer
        }

        fn read_seg(&self, seg: SegRegister) -> u64 {
            match seg {
                SegRegister::CS => 0x00af9a000000ffffu64,
                _ => 0x00cf92000000ffffu64,
            }
        }

        fn read_cr0(&self) -> u64 {
            self.cr0
        }

        fn read_cr4(&self) -> u64 {
            self.cr4
        }

        fn read_reg(&self, reg: Register) -> usize {
            match reg {
                Register::Rax => self.rax,
                Register::Rdx => self.rdx,
                Register::Rcx => self.rcx,
                Register::Rbx => self.rdx,
                Register::Rsp => self.rsp,
                Register::Rbp => self.rbp,
                Register::Rdi => self.rdi,
                Register::Rsi => self.rsi,
                Register::R8 => self.r8,
                Register::R9 => self.r9,
                Register::R10 => self.r10,
                Register::R11 => self.r11,
                Register::R12 => self.r12,
                Register::R13 => self.r13,
                Register::R14 => self.r14,
                Register::R15 => self.r15,
                Register::Rip => self.rip,
            }
        }

        fn write_reg(&mut self, reg: Register, val: usize) {
            match reg {
                Register::Rax => self.rax = val,
                Register::Rdx => self.rdx = val,
                Register::Rcx => self.rcx = val,
                Register::Rbx => self.rdx = val,
                Register::Rsp => self.rsp = val,
                Register::Rbp => self.rbp = val,
                Register::Rdi => self.rdi = val,
                Register::Rsi => self.rsi = val,
                Register::R8 => self.r8 = val,
                Register::R9 => self.r9 = val,
                Register::R10 => self.r10 = val,
                Register::R11 => self.r11 = val,
                Register::R12 => self.r12 = val,
                Register::R13 => self.r13 = val,
                Register::R14 => self.r14 = val,
                Register::R15 => self.r15 = val,
                Register::Rip => self.rip = val,
            }
        }

        fn read_cpl(&self) -> usize {
            0
        }

        fn read_flags(&self) -> usize {
            self.flags
        }

        fn map_linear_addr<T: Copy + 'static>(
            &self,
            la: usize,
            _write: bool,
            _fetch: bool,
        ) -> Result<Box<dyn InsnMachineMem<Item = T>>, InsnError> {
            Ok(Box::new(TestMem { ptr: la as *mut T }))
        }

        fn ioio_in(&self, _port: u16, size: Bytes) -> Result<u64, InsnError> {
            match size {
                Bytes::One => Ok(self.iodata as u8 as u64),
                Bytes::Two => Ok(self.iodata as u16 as u64),
                Bytes::Four => Ok(self.iodata as u32 as u64),
                _ => Err(InsnError::IoIoIn),
            }
        }

        fn ioio_out(&mut self, _port: u16, size: Bytes, data: u64) -> Result<(), InsnError> {
            match size {
                Bytes::One => self.iodata = data as u8 as u64,
                Bytes::Two => self.iodata = data as u16 as u64,
                Bytes::Four => self.iodata = data as u32 as u64,
                _ => return Err(InsnError::IoIoOut),
            }

            Ok(())
        }

        fn translate_linear_addr(
            &self,
            la: usize,
            _write: bool,
            _fetch: bool,
        ) -> Result<(usize, bool), InsnError> {
            Ok((la, false))
        }

        fn handle_mmio_read(
            &self,
            pa: usize,
            _shared: bool,
            size: Bytes,
        ) -> Result<u64, InsnError> {
            if pa != &raw const self.mmio_reg as usize {
                return Ok(0);
            }

            match size {
                Bytes::One => Ok(unsafe { *(pa as *const u8) } as u64),
                Bytes::Two => Ok(unsafe { *(pa as *const u16) } as u64),
                Bytes::Four => Ok(unsafe { *(pa as *const u32) } as u64),
                Bytes::Eight => Ok(unsafe { *(pa as *const u64) }),
                _ => Err(InsnError::HandleMmioRead),
            }
        }

        fn handle_mmio_write(
            &mut self,
            pa: usize,
            _shared: bool,
            size: Bytes,
            data: u64,
        ) -> Result<(), InsnError> {
            if pa != &raw const self.mmio_reg as usize {
                return Ok(());
            }

            match size {
                Bytes::One => unsafe { *(pa as *mut u8) = data as u8 },
                Bytes::Two => unsafe { *(pa as *mut u16) = data as u16 },
                Bytes::Four => unsafe { *(pa as *mut u32) = data as u32 },
                Bytes::Eight => unsafe { *(pa as *mut u64) = data },
                _ => return Err(InsnError::HandleMmioWrite),
            }
            Ok(())
        }
    }

    #[cfg(test)]
    impl<T: Copy> InsnMachineMem for TestMem<T> {
        type Item = T;

        unsafe fn mem_read(&self) -> Result<Self::Item, InsnError> {
            Ok(unsafe { *(self.ptr) })
        }

        unsafe fn mem_write(&mut self, data: Self::Item) -> Result<(), InsnError> {
            unsafe {
                *(self.ptr) = data;
            }
            Ok(())
        }
    }

    #[cfg(fuzzing)]
    impl<T: Copy> InsnMachineMem for TestMem<T> {
        type Item = T;

        unsafe fn mem_read(&self) -> Result<Self::Item, InsnError> {
            Err(InsnError::MemRead)
        }

        unsafe fn mem_write(&mut self, _data: Self::Item) -> Result<(), InsnError> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::*;
    use super::*;
    use crate::cpu::registers::RFlags;

    #[test]
    fn test_decode_inb() {
        let mut testctx = TestCtx {
            iodata: 0xab,
            ..Default::default()
        };
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xE4,
            TEST_PORT as u8,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::In(Operand::Imm(Immediate::U8(TEST_PORT as u8)), Bytes::One)
        );
        assert_eq!(decoded.size(), 2);
        assert_eq!(testctx.rax as u64, testctx.iodata);

        let mut testctx = TestCtx {
            rdx: TEST_PORT as usize,
            iodata: 0xab,
            ..Default::default()
        };
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xEC, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::In(Operand::rdx(), Bytes::One)
        );
        assert_eq!(decoded.size(), 1);
        assert_eq!(testctx.rax as u64, testctx.iodata);
    }

    #[test]
    fn test_decode_inw() {
        let mut testctx = TestCtx {
            iodata: 0xabcd,
            ..Default::default()
        };
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66,
            0xE5,
            TEST_PORT as u8,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::In(Operand::Imm(Immediate::U8(TEST_PORT as u8)), Bytes::Two)
        );
        assert_eq!(decoded.size(), 3);
        assert_eq!(testctx.rax as u64, testctx.iodata);

        let mut testctx = TestCtx {
            rdx: TEST_PORT as usize,
            iodata: 0xabcd,
            ..Default::default()
        };
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0xED, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::In(Operand::rdx(), Bytes::Two)
        );
        assert_eq!(decoded.size(), 2);
        assert_eq!(testctx.rax as u64, testctx.iodata);
    }

    #[test]
    fn test_decode_inl() {
        let mut testctx = TestCtx {
            iodata: 0xabcdef01,
            ..Default::default()
        };
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xE5,
            TEST_PORT as u8,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::In(Operand::Imm(Immediate::U8(TEST_PORT as u8)), Bytes::Four)
        );
        assert_eq!(decoded.size(), 2);
        assert_eq!(testctx.rax as u64, testctx.iodata);

        let mut testctx = TestCtx {
            rdx: TEST_PORT as usize,
            iodata: 0xabcdef01,
            ..Default::default()
        };
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xED, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::In(Operand::rdx(), Bytes::Four)
        );
        assert_eq!(decoded.size(), 1);
        assert_eq!(testctx.rax as u64, testctx.iodata);
    }

    #[test]
    fn test_decode_outb() {
        let mut testctx = TestCtx {
            rax: 0xab,
            ..Default::default()
        };
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xE6,
            TEST_PORT as u8,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::Out(Operand::Imm(Immediate::U8(TEST_PORT as u8)), Bytes::One)
        );
        assert_eq!(decoded.size(), 2);
        assert_eq!(testctx.rax as u64, testctx.iodata);

        let mut testctx = TestCtx {
            rax: 0xab,
            rdx: TEST_PORT as usize,
            ..Default::default()
        };
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xEE, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::Out(Operand::rdx(), Bytes::One)
        );
        assert_eq!(decoded.size(), 1);
        assert_eq!(testctx.rax as u64, testctx.iodata);
    }

    #[test]
    fn test_decode_outw() {
        let mut testctx = TestCtx {
            rax: 0xabcd,
            ..Default::default()
        };
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66,
            0xE7,
            TEST_PORT as u8,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::Out(Operand::Imm(Immediate::U8(TEST_PORT as u8)), Bytes::Two)
        );
        assert_eq!(decoded.size(), 3);
        assert_eq!(testctx.rax as u64, testctx.iodata);

        let mut testctx = TestCtx {
            rax: 0xabcd,
            rdx: TEST_PORT as usize,
            ..Default::default()
        };
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0xEF, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::Out(Operand::rdx(), Bytes::Two)
        );
        assert_eq!(decoded.size(), 2);
        assert_eq!(testctx.rax as u64, testctx.iodata);
    }

    #[test]
    fn test_decode_outl() {
        let mut testctx = TestCtx {
            rax: 0xabcdef01,
            ..Default::default()
        };
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xE7,
            TEST_PORT as u8,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::Out(Operand::Imm(Immediate::U8(TEST_PORT as u8)), Bytes::Four)
        );
        assert_eq!(decoded.size(), 2);
        assert_eq!(testctx.rax as u64, testctx.iodata);

        let mut testctx = TestCtx {
            rax: 0xabcdef01,
            rdx: TEST_PORT as usize,
            ..Default::default()
        };
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xEF, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(
            decoded.insn().unwrap(),
            DecodedInsn::Out(Operand::rdx(), Bytes::Four)
        );
        assert_eq!(decoded.size(), 1);
        assert_eq!(testctx.rax as u64, testctx.iodata);
    }

    #[test]
    fn test_decode_cpuid() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x0F, 0xA2, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx::default()).unwrap();
        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Cpuid);
        assert_eq!(decoded.size(), 2);
    }

    #[test]
    fn test_decode_wrmsr() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x0F, 0x30, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx::default()).unwrap();
        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Wrmsr);
        assert_eq!(decoded.size(), 2);
    }

    #[test]
    fn test_decode_rdmsr() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x0F, 0x32, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx::default()).unwrap();
        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Rdmsr);
        assert_eq!(decoded.size(), 2);
    }

    #[test]
    fn test_decode_rdtsc() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x0F, 0x31, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx::default()).unwrap();
        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Rdtsc);
        assert_eq!(decoded.size(), 2);
    }

    #[test]
    fn test_decode_rdtscp() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x0F, 0x01, 0xF9, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let decoded = insn.decode(&TestCtx::default()).unwrap();
        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Rdtscp);
        assert_eq!(decoded.size(), 3);
    }

    #[test]
    fn test_decode_ins_u8() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xF3, 0x6C, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];
        let iodata: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

        let mut i = 0usize;
        let mut testdata: [u8; 4] = [0; 4];
        let mut testctx = TestCtx {
            rdx: TEST_PORT as usize,
            rcx: testdata.len(),
            rdi: testdata.as_ptr() as usize,
            ..Default::default()
        };
        loop {
            testctx.iodata = *iodata.get(i).unwrap() as u64;
            let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
            decoded.emulate(&mut testctx).unwrap();
            if decoded.size() == 0 {
                i += 1;
                continue;
            }

            assert_eq!(decoded.insn().unwrap(), DecodedInsn::Ins);
            assert_eq!(decoded.size(), 2);
            assert_eq!(0, testctx.rcx);
            assert_eq!(
                testdata.as_ptr() as usize + testdata.len() * Bytes::One as usize,
                testctx.rdi
            );
            assert_eq!(i, testdata.len() - 1);
            for (i, d) in testdata.iter().enumerate() {
                assert_eq!(d, iodata.get(i).unwrap());
            }
            break;
        }

        i = iodata.len() - 1;
        testdata = [0; 4];
        testctx = TestCtx {
            rdx: TEST_PORT as usize,
            rcx: testdata.len(),
            rdi: &raw const testdata[testdata.len() - 1] as usize,
            flags: RFlags::DF.bits(),
            ..Default::default()
        };
        loop {
            testctx.iodata = *iodata.get(i).unwrap() as u64;
            let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
            decoded.emulate(&mut testctx).unwrap();
            if decoded.size() == 0 {
                i = i.checked_sub(1).unwrap();
                continue;
            }

            assert_eq!(decoded.insn().unwrap(), DecodedInsn::Ins);
            assert_eq!(decoded.size(), 2);
            assert_eq!(0, testctx.rcx);
            assert_eq!(
                testdata.as_ptr() as usize - Bytes::One as usize,
                testctx.rdi
            );
            assert_eq!(i, 0);
            for (i, d) in testdata.iter().enumerate() {
                assert_eq!(d, iodata.get(i).unwrap());
            }
            break;
        }
    }

    #[test]
    fn test_decode_ins_u16() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0xF3, 0x6D, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];
        let iodata: [u16; 4] = [0x1234, 0x5678, 0x9abc, 0xdef0];

        let mut i = 0usize;
        let mut testdata: [u16; 4] = [0; 4];
        let mut testctx = TestCtx {
            rdx: TEST_PORT as usize,
            rcx: testdata.len(),
            rdi: testdata.as_ptr() as usize,
            ..Default::default()
        };
        loop {
            testctx.iodata = *iodata.get(i).unwrap() as u64;
            let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
            decoded.emulate(&mut testctx).unwrap();
            if decoded.size() == 0 {
                i += 1;
                continue;
            }

            assert_eq!(decoded.insn().unwrap(), DecodedInsn::Ins);
            assert_eq!(decoded.size(), 3);
            assert_eq!(0, testctx.rcx);
            assert_eq!(
                testdata.as_ptr() as usize + testdata.len() * Bytes::Two as usize,
                testctx.rdi
            );
            assert_eq!(i, testdata.len() - 1);
            for (i, d) in testdata.iter().enumerate() {
                assert_eq!(d, iodata.get(i).unwrap());
            }
            break;
        }

        i = iodata.len() - 1;
        testdata = [0; 4];
        testctx = TestCtx {
            rdx: TEST_PORT as usize,
            rcx: testdata.len(),
            rdi: &raw const testdata[testdata.len() - 1] as usize,
            flags: RFlags::DF.bits(),
            ..Default::default()
        };
        loop {
            testctx.iodata = *iodata.get(i).unwrap() as u64;
            let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
            decoded.emulate(&mut testctx).unwrap();
            if decoded.size() == 0 {
                i = i.checked_sub(1).unwrap();
                continue;
            }

            assert_eq!(decoded.insn().unwrap(), DecodedInsn::Ins);
            assert_eq!(decoded.size(), 3);
            assert_eq!(0, testctx.rcx);
            assert_eq!(
                testdata.as_ptr() as usize - Bytes::Two as usize,
                testctx.rdi
            );
            assert_eq!(i, 0);
            for (i, d) in testdata.iter().enumerate() {
                assert_eq!(d, iodata.get(i).unwrap());
            }
            break;
        }
    }

    #[test]
    fn test_decode_ins_u32() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xF3, 0x6D, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];
        let iodata: [u32; 4] = [0x12345678, 0x9abcdef0, 0x87654321, 0x0fedcba9];

        let mut i = 0usize;
        let mut testdata: [u32; 4] = [0; 4];
        let mut testctx = TestCtx {
            rdx: TEST_PORT as usize,
            rcx: testdata.len(),
            rdi: testdata.as_ptr() as usize,
            ..Default::default()
        };
        loop {
            testctx.iodata = *iodata.get(i).unwrap() as u64;
            let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
            decoded.emulate(&mut testctx).unwrap();
            if decoded.size() == 0 {
                i += 1;
                continue;
            }

            assert_eq!(decoded.insn().unwrap(), DecodedInsn::Ins);
            assert_eq!(decoded.size(), 2);
            assert_eq!(0, testctx.rcx);
            assert_eq!(
                testdata.as_ptr() as usize + testdata.len() * Bytes::Four as usize,
                testctx.rdi
            );
            assert_eq!(i, testdata.len() - 1);
            for (i, d) in testdata.iter().enumerate() {
                assert_eq!(d, iodata.get(i).unwrap());
            }
            break;
        }

        i = iodata.len() - 1;
        testdata = [0; 4];
        testctx = TestCtx {
            rdx: TEST_PORT as usize,
            rcx: testdata.len(),
            rdi: &raw const testdata[testdata.len() - 1] as usize,
            flags: RFlags::DF.bits(),
            ..Default::default()
        };
        loop {
            testctx.iodata = *iodata.get(i).unwrap() as u64;
            let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
            decoded.emulate(&mut testctx).unwrap();
            if decoded.size() == 0 {
                i = i.checked_sub(1).unwrap();
                continue;
            }

            assert_eq!(decoded.insn().unwrap(), DecodedInsn::Ins);
            assert_eq!(decoded.size(), 2);
            assert_eq!(0, testctx.rcx);
            assert_eq!(
                testdata.as_ptr() as usize - Bytes::Four as usize,
                testctx.rdi
            );
            assert_eq!(i, 0);
            for (i, d) in testdata.iter().enumerate() {
                assert_eq!(d, iodata.get(i).unwrap());
            }
            break;
        }
    }

    #[test]
    fn test_decode_outs_u8() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xF3, 0x6E, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];
        let testdata: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

        let mut i = 0usize;
        let mut iodata: [u8; 4] = [0; 4];
        let mut testctx = TestCtx {
            rdx: TEST_PORT as usize,
            rcx: testdata.len(),
            rsi: testdata.as_ptr() as usize,
            ..Default::default()
        };
        loop {
            let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
            decoded.emulate(&mut testctx).unwrap();
            *iodata.get_mut(i).unwrap() = testctx.iodata as u8;
            if decoded.size() == 0 {
                i += 1;
                continue;
            }

            assert_eq!(decoded.insn().unwrap(), DecodedInsn::Outs);
            assert_eq!(decoded.size(), 2);
            assert_eq!(0, testctx.rcx);
            assert_eq!(testdata.as_ptr() as usize + testdata.len(), testctx.rsi);
            assert_eq!(i, testdata.len() - 1);
            for (i, d) in testdata.iter().enumerate() {
                assert_eq!(d, iodata.get(i).unwrap());
            }
            break;
        }

        i = iodata.len() - 1;
        iodata = [0; 4];
        testctx = TestCtx {
            rdx: TEST_PORT as usize,
            rcx: testdata.len(),
            rsi: &raw const testdata[testdata.len() - 1] as usize,
            flags: RFlags::DF.bits(),
            ..Default::default()
        };
        loop {
            let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
            decoded.emulate(&mut testctx).unwrap();
            *iodata.get_mut(i).unwrap() = testctx.iodata as u8;
            if decoded.size() == 0 {
                i = i.checked_sub(1).unwrap();
                continue;
            }

            assert_eq!(decoded.insn().unwrap(), DecodedInsn::Outs);
            assert_eq!(decoded.size(), 2);
            assert_eq!(0, testctx.rcx);
            assert_eq!(
                testdata.as_ptr() as usize - Bytes::One as usize,
                testctx.rsi
            );
            assert_eq!(i, 0);
            for (i, d) in testdata.iter().enumerate() {
                assert_eq!(d, iodata.get(i).unwrap());
            }
            break;
        }
    }

    #[test]
    fn test_decode_outs_u16() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0xF3, 0x6F, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];
        let testdata: [u16; 4] = [0x1234, 0x5678, 0x9abc, 0xdef0];

        let mut i = 0usize;
        let mut iodata: [u16; 4] = [0; 4];
        let mut testctx = TestCtx {
            rdx: TEST_PORT as usize,
            rcx: testdata.len(),
            rsi: testdata.as_ptr() as usize,
            ..Default::default()
        };
        loop {
            let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
            decoded.emulate(&mut testctx).unwrap();
            *iodata.get_mut(i).unwrap() = testctx.iodata as u16;
            if decoded.size() == 0 {
                i += 1;
                continue;
            }

            assert_eq!(decoded.insn().unwrap(), DecodedInsn::Outs);
            assert_eq!(decoded.size(), 3);
            assert_eq!(0, testctx.rcx);
            assert_eq!(
                testdata.as_ptr() as usize + testdata.len() * Bytes::Two as usize,
                testctx.rsi
            );
            assert_eq!(i, testdata.len() - 1);
            for (i, d) in testdata.iter().enumerate() {
                assert_eq!(d, iodata.get(i).unwrap());
            }
            break;
        }

        i = iodata.len() - 1;
        iodata = [0; 4];
        testctx = TestCtx {
            rdx: TEST_PORT as usize,
            rcx: testdata.len(),
            rsi: &raw const testdata[testdata.len() - 1] as usize,
            flags: RFlags::DF.bits(),
            ..Default::default()
        };
        loop {
            let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
            decoded.emulate(&mut testctx).unwrap();
            *iodata.get_mut(i).unwrap() = testctx.iodata as u16;
            if decoded.size() == 0 {
                i = i.checked_sub(1).unwrap();
                continue;
            }

            assert_eq!(decoded.insn().unwrap(), DecodedInsn::Outs);
            assert_eq!(decoded.size(), 3);
            assert_eq!(0, testctx.rcx);
            assert_eq!(
                testdata.as_ptr() as usize - Bytes::Two as usize,
                testctx.rsi
            );
            assert_eq!(i, 0);
            for (i, d) in testdata.iter().enumerate() {
                assert_eq!(d, iodata.get(i).unwrap());
            }
            break;
        }
    }

    #[test]
    fn test_decode_outs_u32() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xF3, 0x6F, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];
        let testdata: [u32; 4] = [0x12345678, 0x9abcdef0, 0xdeadbeef, 0xfeedface];

        let mut i = 0usize;
        let mut iodata: [u32; 4] = [0; 4];
        let mut testctx = TestCtx {
            rdx: TEST_PORT as usize,
            rcx: testdata.len(),
            rsi: testdata.as_ptr() as usize,
            ..Default::default()
        };
        loop {
            let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
            decoded.emulate(&mut testctx).unwrap();
            *iodata.get_mut(i).unwrap() = testctx.iodata as u32;
            if decoded.size() == 0 {
                i += 1;
                continue;
            }

            assert_eq!(decoded.insn().unwrap(), DecodedInsn::Outs);
            assert_eq!(decoded.size(), 2);
            assert_eq!(*testdata.last().unwrap() as u64, testctx.iodata);
            assert_eq!(0, testctx.rcx);
            assert_eq!(
                testdata.as_ptr() as usize + testdata.len() * Bytes::Four as usize,
                testctx.rsi
            );
            assert_eq!(i, testdata.len() - 1);
            for (i, d) in testdata.iter().enumerate() {
                assert_eq!(d, iodata.get(i).unwrap());
            }
            break;
        }

        i = iodata.len() - 1;
        iodata = [0; 4];
        testctx = TestCtx {
            rdx: TEST_PORT as usize,
            rcx: testdata.len(),
            rsi: &raw const testdata[testdata.len() - 1] as usize,
            flags: RFlags::DF.bits(),
            ..Default::default()
        };
        loop {
            let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
            decoded.emulate(&mut testctx).unwrap();
            *iodata.get_mut(i).unwrap() = testctx.iodata as u32;
            if decoded.size() == 0 {
                i = i.checked_sub(1).unwrap();
                continue;
            }

            assert_eq!(decoded.insn().unwrap(), DecodedInsn::Outs);
            assert_eq!(decoded.size(), 2);
            assert_eq!(0, testctx.rcx);
            assert_eq!(
                testdata.as_ptr() as usize - Bytes::Four as usize,
                testctx.rsi
            );
            assert_eq!(i, 0);
            for (i, d) in testdata.iter().enumerate() {
                assert_eq!(d, iodata.get(i).unwrap());
            }
            break;
        }
    }

    #[test]
    fn test_decode_mov_reg_to_rm() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x88, 0x07, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut testctx = TestCtx {
            rax: 0xab,
            ..Default::default()
        };
        testctx.rdi = &raw const testctx.mmio_reg as usize;

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Mov);
        assert_eq!(decoded.size(), 2);
        assert_eq!(testctx.mmio_reg, testctx.rax as u64);

        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x48, 0x89, 0x07, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut testctx = TestCtx {
            rax: 0x1234567890abcdef,
            ..Default::default()
        };
        testctx.rdi = &raw const testctx.mmio_reg as usize;

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Mov);
        assert_eq!(decoded.size(), 3);
        assert_eq!(testctx.mmio_reg, testctx.rax as u64);
    }

    #[test]
    fn test_decode_mov_rm_to_reg() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x8A, 0x07, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut testctx = TestCtx {
            mmio_reg: 0xab,
            ..Default::default()
        };
        testctx.rdi = &raw const testctx.mmio_reg as usize;

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Mov);
        assert_eq!(decoded.size(), 2);
        assert_eq!(testctx.mmio_reg, testctx.rax as u64);

        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x48, 0x8B, 0x07, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut testctx = TestCtx {
            mmio_reg: 0x1234567890abcdef,
            ..Default::default()
        };
        testctx.rdi = &raw const testctx.mmio_reg as usize;

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Mov);
        assert_eq!(decoded.size(), 3);
        assert_eq!(testctx.mmio_reg, testctx.rax as u64);
    }

    #[test]
    fn test_decode_mov_moffset_to_reg() {
        let mut raw_insn: [u8; MAX_INSN_SIZE] = [
            0xA1, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut testctx = TestCtx {
            mmio_reg: 0x12345678,
            ..Default::default()
        };
        let addr = (&raw const testctx.mmio_reg as usize).to_le_bytes();
        raw_insn[1..9].copy_from_slice(&addr);

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Mov);
        assert_eq!(decoded.size(), 9);
        assert_eq!(testctx.mmio_reg, testctx.rax as u64);
    }

    #[test]
    fn test_decode_mov_reg_to_moffset() {
        let mut raw_insn: [u8; MAX_INSN_SIZE] = [
            0xA3, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut testctx = TestCtx {
            rax: 0x12345678,
            ..Default::default()
        };
        let addr = (&raw const testctx.mmio_reg as usize).to_le_bytes();
        raw_insn[1..9].copy_from_slice(&addr);

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Mov);
        assert_eq!(decoded.size(), 9);
        assert_eq!(testctx.mmio_reg, testctx.rax as u64);
    }

    #[test]
    fn test_decode_mov_imm_to_reg() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0xC6, 0x07, 0xab, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut testctx = TestCtx {
            ..Default::default()
        };
        testctx.rdi = &raw const testctx.mmio_reg as usize;

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Mov);
        assert_eq!(decoded.size(), 3);
        assert_eq!(testctx.mmio_reg, 0xab);

        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x48, 0xC7, 0x07, 0x78, 0x56, 0x34, 0x12, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let mut testctx = TestCtx {
            ..Default::default()
        };
        testctx.rdi = &raw const testctx.mmio_reg as usize;

        let decoded = Instruction::new(raw_insn).decode(&testctx).unwrap();
        decoded.emulate(&mut testctx).unwrap();

        assert_eq!(decoded.insn().unwrap(), DecodedInsn::Mov);
        assert_eq!(decoded.size(), 7);
        assert_eq!(testctx.mmio_reg, 0x12345678);
    }

    #[test]
    fn test_decode_failed() {
        let raw_insn: [u8; MAX_INSN_SIZE] = [
            0x66, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41,
        ];

        let insn = Instruction::new(raw_insn);
        let err = insn.decode(&TestCtx::default());

        assert!(err.is_err());
    }
}
