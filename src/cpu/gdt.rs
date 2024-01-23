// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::tss::X86Tss;
use crate::address::VirtAddr;
use crate::locking::{RWLock, ReadLockGuard, WriteLockGuard};
use crate::types::{SVSM_CS, SVSM_DS, SVSM_TSS};
use core::arch::asm;
use core::mem;

#[repr(C, packed(2))]
#[derive(Clone, Copy, Debug)]
struct GDTDesc {
    size: u16,
    addr: VirtAddr,
}

#[derive(Copy, Clone, Debug)]
pub struct GDTEntry(u64);

impl GDTEntry {
    pub const fn from_raw(entry: u64) -> Self {
        Self(entry)
    }

    pub fn to_raw(&self) -> u64 {
        self.0
    }

    pub const fn null() -> Self {
        Self(0u64)
    }

    pub const fn code_64_kernel() -> Self {
        Self(0x00af9a000000ffffu64)
    }

    pub const fn data_64_kernel() -> Self {
        Self(0x00cf92000000ffffu64)
    }
}

const GDT_SIZE: u16 = 8;

#[derive(Copy, Clone, Debug)]
pub struct GDT {
    entries: [GDTEntry; GDT_SIZE as usize],
}

impl GDT {
    pub const fn new() -> Self {
        GDT {
            entries: [
                GDTEntry::null(),
                GDTEntry::code_64_kernel(),
                GDTEntry::data_64_kernel(),
                GDTEntry::null(),
                GDTEntry::null(),
                GDTEntry::null(),
                GDTEntry::null(),
                GDTEntry::null(),
            ],
        }
    }

    pub fn base_limit(&self) -> (u64, u32) {
        let gdt_entries = GDT_SIZE as usize;
        let base = (self as *const GDT) as u64;
        let limit = ((mem::size_of::<u64>() * gdt_entries) - 1) as u32;
        (base, limit)
    }

    fn descriptor(&self) -> GDTDesc {
        GDTDesc {
            size: (GDT_SIZE * 8) - 1,
            addr: VirtAddr::from(self.entries.as_ptr()),
        }
    }

    pub fn load(&self) {
        let gdt_desc = self.descriptor();
        unsafe {
            asm!(r#" /* Load GDT */
                 lgdt   (%rax)

                 /* Reload data segments */
                 movw   %cx, %ds
                 movw   %cx, %es
                 movw   %cx, %fs
                 movw   %cx, %gs
                 movw   %cx, %ss

                 /* Reload code segment */
                 pushq  %rdx
                 leaq   1f(%rip), %rax
                 pushq  %rax
                 lretq
            1:
                 "#,
                in("rax") &gdt_desc,
                in("rdx") SVSM_CS,
                in("rcx") SVSM_DS,
                options(att_syntax));
        }
    }

    fn set_tss_entry(&mut self, desc0: GDTEntry, desc1: GDTEntry) {
        let idx = (SVSM_TSS / 8) as usize;

        self.entries[idx] = desc0;
        self.entries[idx + 1] = desc1;
    }

    fn clear_tss_entry(&mut self) {
        let idx = (SVSM_TSS / 8) as usize;

        self.entries[idx] = GDTEntry::null();
        self.entries[idx + 1] = GDTEntry::null();
    }

    pub fn load_tss(&mut self, tss: &X86Tss) {
        let (desc0, desc1) = tss.to_gdt_entry();

        self.set_tss_entry(desc0, desc1);
        unsafe {
            asm!("ltr %ax", in("ax") SVSM_TSS, options(att_syntax));
        }
        self.clear_tss_entry()
    }
}

static GDT: RWLock<GDT> = RWLock::new(GDT::new());

pub fn gdt() -> ReadLockGuard<'static, GDT> {
    GDT.lock_read()
}

pub fn gdt_mut() -> WriteLockGuard<'static, GDT> {
    GDT.lock_write()
}
