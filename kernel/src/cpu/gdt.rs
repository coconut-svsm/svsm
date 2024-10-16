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
#[derive(Clone, Copy, Debug, Default)]
struct GDTDesc {
    size: u16,
    addr: VirtAddr,
}

#[derive(Copy, Clone, Debug, Default)]
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

    pub const fn code_64_user() -> Self {
        Self(0x00affb000000ffffu64)
    }

    pub const fn data_64_user() -> Self {
        Self(0x00cff2000000ffffu64)
    }
}

const GDT_SIZE: u16 = 8;

#[derive(Copy, Clone, Debug, Default)]
pub struct GDT {
    entries: [GDTEntry; GDT_SIZE as usize],
}

impl GDT {
    pub const fn new() -> Self {
        Self {
            entries: [
                GDTEntry::null(),
                GDTEntry::code_64_kernel(),
                GDTEntry::data_64_kernel(),
                GDTEntry::code_64_user(),
                GDTEntry::data_64_user(),
                GDTEntry::null(),
                GDTEntry::null(),
                GDTEntry::null(),
            ],
        }
    }

    fn set_tss_entry(&mut self, desc0: GDTEntry, desc1: GDTEntry) {
        let idx = (SVSM_TSS / 8) as usize;

        let tss_entries = &self.entries[idx..idx + 1].as_mut_ptr();

        unsafe {
            tss_entries.add(0).write_volatile(desc0);
            tss_entries.add(1).write_volatile(desc1);
        }
    }

    fn clear_tss_entry(&mut self) {
        self.set_tss_entry(GDTEntry::null(), GDTEntry::null());
    }

    pub fn load_tss(&mut self, tss: &X86Tss) {
        let (desc0, desc1) = tss.to_gdt_entry();

        unsafe {
            self.set_tss_entry(desc0, desc1);
            asm!("ltr %ax", in("ax") SVSM_TSS, options(att_syntax));
            self.clear_tss_entry()
        }
    }

    pub fn kernel_cs(&self) -> GDTEntry {
        self.entries[(SVSM_CS / 8) as usize]
    }

    pub fn kernel_ds(&self) -> GDTEntry {
        self.entries[(SVSM_DS / 8) as usize]
    }
}

impl ReadLockGuard<'static, GDT> {
    /// Load a GDT. Its lifetime must be static so that its entries are
    /// always available to the CPU.
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

    fn descriptor(&self) -> GDTDesc {
        GDTDesc {
            size: (GDT_SIZE * 8) - 1,
            addr: VirtAddr::from(self.entries.as_ptr()),
        }
    }

    pub fn base_limit(&self) -> (u64, u16) {
        let gdt_entries = GDT_SIZE as usize;
        let base: *const GDT = core::ptr::from_ref(self);
        let limit = ((mem::size_of::<u64>() * gdt_entries) - 1) as u16;
        (base as u64, limit)
    }
}

static GDT: RWLock<GDT> = RWLock::new(GDT::new());

pub fn gdt() -> ReadLockGuard<'static, GDT> {
    GDT.lock_read()
}

pub fn gdt_mut() -> WriteLockGuard<'static, GDT> {
    GDT.lock_write()
}
