// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
use crate::cpu::registers::{X86GeneralRegs, X86InterruptFrame};
use crate::locking::{RWLock, ReadLockGuard, WriteLockGuard};
use crate::types::SVSM_CS;
use core::arch::{asm, global_asm};
use core::mem;

pub const _DE_VECTOR: usize = 0;
pub const _DB_VECTOR: usize = 1;
pub const _NMI_VECTOR: usize = 2;
pub const BP_VECTOR: usize = 3;
pub const _OF_VECTOR: usize = 4;
pub const _BR_VECTOR: usize = 5;
pub const _UD_VECTOR: usize = 6;
pub const _NM_VECTOR: usize = 7;
pub const DF_VECTOR: usize = 8;
pub const _CSO_VECTOR: usize = 9;
pub const _TS_VECTOR: usize = 10;
pub const _NP_VECTOR: usize = 11;
pub const _SS_VECTOR: usize = 12;
pub const GP_VECTOR: usize = 13;
pub const PF_VECTOR: usize = 14;
pub const _MF_VECTOR: usize = 16;
pub const _AC_VECTOR: usize = 17;
pub const _MCE_VECTOR: usize = 18;
pub const _XF_VECTOR: usize = 19;
pub const _CP_VECTOR: usize = 21;
pub const HV_VECTOR: usize = 28;
pub const VC_VECTOR: usize = 29;
pub const _SX_VECTOR: usize = 30;

pub const PF_ERROR_WRITE: usize = 2;

#[repr(C, packed)]
#[derive(Default, Debug, Clone, Copy)]
pub struct X86ExceptionContext {
    pub regs: X86GeneralRegs,
    pub vector: usize,
    pub error_code: usize,
    pub frame: X86InterruptFrame,
}

#[derive(Copy, Clone, Default, Debug)]
#[repr(C, packed)]
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

const IDT_TYPE_MASK: u64 = 0xeu64 << 40; // Only interrupt gates for now
const IDT_PRESENT_MASK: u64 = 0x1u64 << 47;
const IDT_CS_SHIFT: u64 = 16;

const IDT_IST_MASK: u64 = 0x7;
const IDT_IST_SHIFT: u64 = 32;

impl IdtEntry {
    fn create(target: VirtAddr, cs: u16, ist: u8) -> Self {
        let vaddr = target.bits() as u64;
        let cs_mask = (cs as u64) << IDT_CS_SHIFT;
        let ist_mask = ((ist as u64) & IDT_IST_MASK) << IDT_IST_SHIFT;
        let low = (vaddr & IDT_TARGET_MASK_1) << IDT_TARGET_MASK_1_SHIFT
            | (vaddr & IDT_TARGET_MASK_2) << IDT_TARGET_MASK_2_SHIFT
            | IDT_TYPE_MASK
            | IDT_PRESENT_MASK
            | cs_mask
            | ist_mask;
        let high = (vaddr & IDT_TARGET_MASK_3) >> IDT_TARGET_MASK_3_SHIFT;

        IdtEntry { low, high }
    }

    pub fn entry(target: VirtAddr) -> Self {
        IdtEntry::create(target, SVSM_CS, 0)
    }

    pub fn ist_entry(target: VirtAddr, ist: u8) -> Self {
        IdtEntry::create(target, SVSM_CS, ist)
    }

    pub const fn no_handler() -> Self {
        IdtEntry { low: 0, high: 0 }
    }
}

const IDT_ENTRIES: usize = 256;

#[repr(C, packed)]
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
            self.set_entry(idx, IdtEntry::entry(handlers + (32 * idx)));
        }

        self
    }

    pub fn set_entry(&mut self, idx: usize, entry: IdtEntry) -> &mut Self {
        self.entries[idx] = entry;

        self
    }

    pub fn load(&self) -> &Self {
        let desc: IdtDesc = IdtDesc {
            size: (IDT_ENTRIES * 16) as u16,
            address: VirtAddr::from(self.entries.as_ptr()),
        };

        unsafe {
            asm!("lidt (%rax)", in("rax") &desc, options(att_syntax));
        }

        self
    }

    pub fn base_limit(&self) -> (u64, u32) {
        let base = (self as *const IDT) as u64;
        let limit = (IDT_ENTRIES * mem::size_of::<IdtEntry>()) as u32;
        (base, limit)
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

    unsafe {
        asm!("lidt (%rax)
              int3", in("rax") &desc, options(att_syntax));
    }
}

#[cfg(feature = "enable-stacktrace")]
extern "C" {
    static generic_idt_handler_return: u8;
}

#[cfg(feature = "enable-stacktrace")]
pub fn is_exception_handler_return_site(rip: VirtAddr) -> bool {
    let addr = unsafe { VirtAddr::from(&generic_idt_handler_return as *const u8) };
    addr == rip
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

        addq    $16, %rsp /* Skip vector and error code */

        iretq
        "#,
    options(att_syntax)
);
