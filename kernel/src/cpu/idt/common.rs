// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::address::{Address, VirtAddr};
use crate::cpu::control_regs::{read_cr0, read_cr4};
use crate::cpu::efer::read_efer;
use crate::cpu::gdt::GLOBAL_GDT;
use crate::cpu::registers::{X86GeneralRegs, X86InterruptFrame};
use crate::cpu::shadow_stack::is_cet_ss_supported;
use crate::insn_decode::{InsnError, InsnMachineCtx, InsnMachineMem, Register, SegRegister};
use crate::locking::{RWLock, ReadLockGuard, WriteLockGuard};
use crate::mm::GuestPtr;
use crate::platform::SVSM_PLATFORM;
use crate::types::{Bytes, SVSM_CS};
use alloc::boxed::Box;
use core::arch::{asm, global_asm};
use core::mem;
use core::ops::Deref;

pub const DE_VECTOR: usize = 0;
pub const DB_VECTOR: usize = 1;
pub const NMI_VECTOR: usize = 2;
pub const BP_VECTOR: usize = 3;
pub const OF_VECTOR: usize = 4;
pub const BR_VECTOR: usize = 5;
pub const UD_VECTOR: usize = 6;
pub const NM_VECTOR: usize = 7;
pub const DF_VECTOR: usize = 8;
pub const CSO_VECTOR: usize = 9;
pub const TS_VECTOR: usize = 10;
pub const NP_VECTOR: usize = 11;
pub const SS_VECTOR: usize = 12;
pub const GP_VECTOR: usize = 13;
pub const PF_VECTOR: usize = 14;
pub const MF_VECTOR: usize = 16;
pub const AC_VECTOR: usize = 17;
pub const MCE_VECTOR: usize = 18;
pub const XF_VECTOR: usize = 19;
pub const VE_VECTOR: usize = 20;
pub const CP_VECTOR: usize = 21;
pub const HV_VECTOR: usize = 28;
pub const VC_VECTOR: usize = 29;
pub const SX_VECTOR: usize = 30;

pub const INT_INJ_VECTOR: usize = 0x50;
pub const IPI_VECTOR: usize = 0xE0;

bitflags::bitflags! {
    /// Page fault error code flags.
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub struct PageFaultError :u32 {
        const P     = 1 << 0;
        const W     = 1 << 1;
        const U     = 1 << 2;
        const R     = 1 << 3;
        const I     = 1 << 4;
    }
}

#[repr(C, packed)]
#[derive(Default, Debug, Clone, Copy)]
pub struct X86ExceptionContext {
    pub ssp: u64,
    _padding: [u8; 8],
    pub regs: X86GeneralRegs,
    pub error_code: usize,
    pub frame: X86InterruptFrame,
}

impl X86ExceptionContext {
    /// # Safety
    ///
    /// The caller must ensure to update the rest of the execution state as
    /// actual hardware would have done it (e.g. for MMIO emulation, CPUID,
    /// MSR, etc.).
    pub unsafe fn set_rip(&mut self, new_rip: usize) {
        self.frame.rip = new_rip;

        if is_cet_ss_supported() {
            let return_on_stack = (self.ssp + 8) as *const usize;
            let return_on_stack_val = new_rip;
            // SAFETY: Inline assembly to update the instruction pointer on
            // the shadow stack. The safety of the RIP value is delegated to
            // the caller of this function which is unsafe.
            unsafe {
                asm!(
                    "wrssq [{}], {}",
                    in(reg) return_on_stack,
                    in(reg) return_on_stack_val
                );
            }
        }
    }
}

impl InsnMachineCtx for X86ExceptionContext {
    fn read_efer(&self) -> u64 {
        read_efer().bits()
    }

    fn read_seg(&self, seg: SegRegister) -> u64 {
        match seg {
            SegRegister::CS => GLOBAL_GDT.kernel_cs().to_raw(),
            _ => GLOBAL_GDT.kernel_ds().to_raw(),
        }
    }

    fn read_cr0(&self) -> u64 {
        read_cr0().bits()
    }

    fn read_cr4(&self) -> u64 {
        read_cr4().bits()
    }

    fn read_reg(&self, reg: Register) -> usize {
        match reg {
            Register::Rax => self.regs.rax,
            Register::Rdx => self.regs.rdx,
            Register::Rcx => self.regs.rcx,
            Register::Rbx => self.regs.rdx,
            Register::Rsp => self.frame.rsp,
            Register::Rbp => self.regs.rbp,
            Register::Rdi => self.regs.rdi,
            Register::Rsi => self.regs.rsi,
            Register::R8 => self.regs.r8,
            Register::R9 => self.regs.r9,
            Register::R10 => self.regs.r10,
            Register::R11 => self.regs.r11,
            Register::R12 => self.regs.r12,
            Register::R13 => self.regs.r13,
            Register::R14 => self.regs.r14,
            Register::R15 => self.regs.r15,
            Register::Rip => self.frame.rip,
        }
    }

    fn read_flags(&self) -> usize {
        self.frame.flags
    }

    fn write_reg(&mut self, reg: Register, val: usize) {
        match reg {
            Register::Rax => self.regs.rax = val,
            Register::Rdx => self.regs.rdx = val,
            Register::Rcx => self.regs.rcx = val,
            Register::Rbx => self.regs.rdx = val,
            Register::Rsp => self.frame.rsp = val,
            Register::Rbp => self.regs.rbp = val,
            Register::Rdi => self.regs.rdi = val,
            Register::Rsi => self.regs.rsi = val,
            Register::R8 => self.regs.r8 = val,
            Register::R9 => self.regs.r9 = val,
            Register::R10 => self.regs.r10 = val,
            Register::R11 => self.regs.r11 = val,
            Register::R12 => self.regs.r12 = val,
            Register::R13 => self.regs.r13 = val,
            Register::R14 => self.regs.r14 = val,
            Register::R15 => self.regs.r15 = val,
            Register::Rip => self.frame.rip = val,
        }
    }

    fn read_cpl(&self) -> usize {
        self.frame.cs & 3
    }

    fn map_linear_addr<T: Copy + 'static>(
        &self,
        la: usize,
        _write: bool,
        _fetch: bool,
    ) -> Result<Box<dyn InsnMachineMem<Item = T>>, InsnError> {
        if user_mode(self) {
            todo!();
        } else {
            Ok(Box::new(GuestPtr::<T>::new(VirtAddr::from(la))))
        }
    }

    fn ioio_perm(&self, _port: u16, _size: Bytes, _io_read: bool) -> bool {
        // Check if the IO port can be supported by user mode
        todo!();
    }

    fn ioio_in(&self, port: u16, size: Bytes) -> Result<u64, InsnError> {
        let io_port = SVSM_PLATFORM.get_io_port();
        let data = match size {
            Bytes::One => io_port.inb(port) as u64,
            Bytes::Two => io_port.inw(port) as u64,
            Bytes::Four => io_port.inl(port) as u64,
            _ => return Err(InsnError::IoIoIn),
        };
        Ok(data)
    }

    fn ioio_out(&mut self, port: u16, size: Bytes, data: u64) -> Result<(), InsnError> {
        let io_port = SVSM_PLATFORM.get_io_port();
        match size {
            Bytes::One => io_port.outb(port, data as u8),
            Bytes::Two => io_port.outw(port, data as u16),
            Bytes::Four => io_port.outl(port, data as u32),
            _ => return Err(InsnError::IoIoOut),
        }
        Ok(())
    }
}

pub fn user_mode(ctxt: &X86ExceptionContext) -> bool {
    (ctxt.frame.cs & 3) == 3
}

// The base addresses of the IDT should be aligned on an 8-byte boundary
// to maximize performance of cache line fills.
#[derive(Copy, Clone, Default, Debug)]
#[repr(C, packed(8))]
pub struct IdtEntry {
    low: u64,
    high: u64,
}

const IDT_TARGET_MASK_1: u64 = 0x0000_0000_0000_ffff;
const IDT_TARGET_MASK_2: u64 = 0x0000_0000_ffff_0000;
const IDT_TARGET_MASK_3: u64 = 0xffff_ffff_0000_0000;

const IDT_TARGET_MASK_1_SHIFT: u64 = 0;
const IDT_TARGET_MASK_2_SHIFT: u64 = 48 - 16;
const IDT_TARGET_MASK_3_SHIFT: u64 = 32;

const IDT_TYPE_MASK: u8 = 0x0f;
const IDT_TYPE_SHIFT: u64 = 40;
const IDT_TYPE_CALL: u8 = 0x0c;
const IDT_TYPE_INT: u8 = 0x0e;
const IDT_TYPE_TRAP: u8 = 0x0f;

fn idt_type_mask(t: u8) -> u64 {
    ((t & IDT_TYPE_MASK) as u64) << IDT_TYPE_SHIFT
}

const IDT_DPL_MASK: u8 = 0x03;
const IDT_DPL_SHIFT: u64 = 45;

fn idt_dpl_mask(dpl: u8) -> u64 {
    ((dpl & IDT_DPL_MASK) as u64) << IDT_DPL_SHIFT
}

const IDT_PRESENT_MASK: u64 = 0x1u64 << 47;
const IDT_CS_SHIFT: u64 = 16;

const IDT_IST_MASK: u64 = 0x7;
const IDT_IST_SHIFT: u64 = 32;

impl IdtEntry {
    fn create(target: VirtAddr, cs: u16, desc_type: u8, dpl: u8, ist: u8) -> Self {
        let vaddr = target.bits() as u64;
        let cs_mask = (cs as u64) << IDT_CS_SHIFT;
        let ist_mask = ((ist as u64) & IDT_IST_MASK) << IDT_IST_SHIFT;
        let low = (vaddr & IDT_TARGET_MASK_1) << IDT_TARGET_MASK_1_SHIFT
            | (vaddr & IDT_TARGET_MASK_2) << IDT_TARGET_MASK_2_SHIFT
            | idt_type_mask(desc_type)
            | IDT_PRESENT_MASK
            | idt_dpl_mask(dpl)
            | cs_mask
            | ist_mask;
        let high = (vaddr & IDT_TARGET_MASK_3) >> IDT_TARGET_MASK_3_SHIFT;

        IdtEntry { low, high }
    }

    pub fn raw_entry(target: VirtAddr) -> Self {
        IdtEntry::create(target, SVSM_CS, IDT_TYPE_INT, 0, 0)
    }

    pub fn entry(handler: unsafe extern "C" fn()) -> Self {
        let target = VirtAddr::from(handler as *const ());
        IdtEntry::create(target, SVSM_CS, IDT_TYPE_INT, 0, 0)
    }

    pub fn user_entry(handler: unsafe extern "C" fn()) -> Self {
        let target = VirtAddr::from(handler as *const ());
        IdtEntry::create(target, SVSM_CS, IDT_TYPE_INT, 3, 0)
    }

    pub fn ist_entry(handler: unsafe extern "C" fn(), ist: u8) -> Self {
        let target = VirtAddr::from(handler as *const ());
        IdtEntry::create(target, SVSM_CS, IDT_TYPE_INT, 0, ist)
    }

    pub fn trap_entry(handler: unsafe extern "C" fn()) -> Self {
        let target = VirtAddr::from(handler as *const ());
        IdtEntry::create(target, SVSM_CS, IDT_TYPE_TRAP, 0, 0)
    }

    pub fn call_entry(handler: unsafe extern "C" fn()) -> Self {
        let target = VirtAddr::from(handler as *const ());
        IdtEntry::create(target, SVSM_CS, IDT_TYPE_CALL, 3, 0)
    }

    pub const fn no_handler() -> Self {
        IdtEntry { low: 0, high: 0 }
    }
}

const IDT_ENTRIES: usize = 256;

#[repr(C, packed(2))]
#[derive(Default, Clone, Copy, Debug)]
struct IdtDesc {
    size: u16,
    address: VirtAddr,
}

#[derive(Copy, Clone, Debug)]
pub struct IDT {
    entries: [IdtEntry; IDT_ENTRIES],
}

impl IDT {
    pub const fn new() -> Self {
        IDT {
            entries: [IdtEntry::no_handler(); IDT_ENTRIES],
        }
    }

    pub fn init(&mut self, handler_array: *const u8, size: usize) -> &mut Self {
        // Set IDT handlers
        let handlers = VirtAddr::from(handler_array);

        for idx in 0..size {
            self.set_entry(idx, IdtEntry::raw_entry(handlers + (32 * idx)));
        }

        self
    }

    pub fn set_entry(&mut self, idx: usize, entry: IdtEntry) -> &mut Self {
        self.entries[idx] = entry;

        self
    }

    /// Load an IDT.
    /// # Safety
    /// The caller must guarantee that the IDT lifetime must be static so that
    /// its entries are always available to the CPU.
    pub unsafe fn load(&self) {
        let desc: IdtDesc = IdtDesc {
            size: (IDT_ENTRIES * 16) as u16,
            address: VirtAddr::from(self.entries.as_ptr()),
        };

        // SAFETY: Inline assembly to load an IDT. `'static` lifetime ensures
        // that address is always available for the CPU.
        unsafe {
            asm!("lidt (%rax)", in("rax") &desc, options(att_syntax));
        }
    }
}

impl Default for IDT {
    fn default() -> Self {
        Self::new()
    }
}

impl WriteLockGuard<'static, IDT> {
    pub fn load(&self) {
        // SAFETY: the lifetime of the lock guard is static, so the safety
        // requirement of IDT::load are met.
        unsafe {
            self.deref().load();
        }
    }
}

impl ReadLockGuard<'static, IDT> {
    pub fn load(&self) {
        // SAFETY: the lifetime of the lock guard is static, so the safety
        // requirement of IDT::load are met.
        unsafe {
            self.deref().load();
        }
    }

    pub fn base_limit(&self) -> (u64, u16) {
        let base: *const IDT = core::ptr::from_ref(self);
        let limit = (IDT_ENTRIES * mem::size_of::<IdtEntry>()) as u16;
        (base as u64, limit)
    }
}

static IDT: RWLock<IDT> = RWLock::new(IDT::new());

pub fn idt() -> ReadLockGuard<'static, IDT> {
    IDT.lock_read()
}

pub fn idt_mut() -> WriteLockGuard<'static, IDT> {
    IDT.lock_write()
}

pub fn triple_fault() {
    let desc: IdtDesc = IdtDesc {
        size: 0,
        address: VirtAddr::from(0u64),
    };

    // SAFETY: This ends execution, this function will not return so memory
    // safety is not an issue.
    unsafe {
        asm!("lidt (%rax)
              int3", in("rax") &desc, options(att_syntax));
    }
}

extern "C" {
    static entry_code_start: u8;
    static entry_code_end: u8;
}

pub fn is_exception_handler_return_site(rip: VirtAddr) -> bool {
    let start = VirtAddr::from(&raw const entry_code_start);
    let end = VirtAddr::from(&raw const entry_code_end);
    (start..end).contains(&rip)
}

global_asm!(
    r#"
        /* Needed by the stack unwinder to recognize exception frames. */
        .globl generic_idt_handler_return
    generic_idt_handler_return:

        popq    %r15
        popq    %r14
        popq    %r13
        popq    %r12
        popq    %r11
        popq    %r10
        popq    %r9
        popq    %r8
        popq    %rbp
        popq    %rdi
        popq    %rsi
        popq    %rdx
        popq    %rcx
        popq    %rbx
        popq    %rax

        addq    $8, %rsp /* Skip error code */

        iretq
        "#,
    options(att_syntax)
);

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
pub enum IdtEventType {
    Unknown = 0,
    External,
    Software,
}

impl IdtEventType {
    pub fn is_external_interrupt(&self, vector: usize) -> bool {
        match self {
            Self::External => true,
            Self::Software => false,
            Self::Unknown => SVSM_PLATFORM.is_external_interrupt(vector),
        }
    }
}
