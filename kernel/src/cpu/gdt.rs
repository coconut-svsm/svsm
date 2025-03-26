// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::tss::X86Tss;
use crate::address::VirtAddr;
use crate::types::{SVSM_CS, SVSM_DS, SVSM_TSS};
use core::arch::asm;
use core::mem;

#[repr(C, packed(2))]
#[derive(Clone, Copy, Debug, Default)]
struct GDTDesc {
    size: u16,
    addr: VirtAddr,
}

// The base address of the GDT should be aligned on an 8-byte boundary
// to yield the best processor performance.
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
        Self(0x00af9b000000ffffu64)
    }

    pub const fn data_64_kernel() -> Self {
        Self(0x00cf93000000ffffu64)
    }

    pub const fn code_64_user() -> Self {
        Self(0x00affb000000ffffu64)
    }

    pub const fn data_64_user() -> Self {
        Self(0x00cff3000000ffffu64)
    }
}

const GDT_SIZE: u16 = 8;

pub static GLOBAL_GDT: GDT = GDT::new();

#[derive(Clone, Debug, Default)]
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

        // SAFETY:
        // For add():
        //   - idx and idx + size_of::<GDTEntry>() don't overflow isize.
        //   - the borrow checker guarantees that self is still allocated
        //   - self.entries[6:8] fits in self's allocation.
        // For write_volatile():
        //   - the borrow checker guarantees that self.entries is allocated
        //   - alignment is checked inside
        unsafe {
            assert_eq!(align_of_val(&tss_entries.add(0)), align_of::<GDTEntry>());
            assert_eq!(align_of_val(&tss_entries.add(1)), align_of::<GDTEntry>());

            tss_entries.add(0).write_volatile(desc0);
            tss_entries.add(1).write_volatile(desc1);
        }
    }

    fn clear_tss_entry(&mut self) {
        self.set_tss_entry(GDTEntry::null(), GDTEntry::null());
    }

    pub fn load_tss(&mut self, tss: &'static X86Tss) {
        let (desc0, desc1) = tss.to_gdt_entry();

        self.set_tss_entry(desc0, desc1);
        // SAFETY: loading task register must me done in assembly.
        // tss is ensured to have a static lifetime so this is safe.
        unsafe { asm!("ltr %ax", in("ax") SVSM_TSS, options(att_syntax)) };
        self.clear_tss_entry()
    }

    pub fn kernel_cs(&self) -> GDTEntry {
        self.entries[(SVSM_CS / 8) as usize]
    }

    pub fn kernel_ds(&self) -> GDTEntry {
        self.entries[(SVSM_DS / 8) as usize]
    }

    /// Makes this GDT the active GDT.
    pub fn load(&self) {
        let gdt_desc = self.descriptor();
        // SAFETY: loading the GDT must be done in assembly.  Use of the GDT
        // descriptor is safe because it describes a valid objct which
        // implements Drop to clean up if the GDT object ever ceases to be
        // valid.
        unsafe {
            asm!("lgdt ({0})",
                 in(reg) &gdt_desc,
                 options(att_syntax));
        }
    }

    /// Loads all selectors from the current GDT.
    pub fn load_selectors(&self) {
        self.load();
        // SAFETY: assembly is required to load segments from the GDT.  In the
        // x86-64 architecture, the chosen selector values do not affect the
        // validity of any memory addresses and thus cannot impact memory
        // safety.
        unsafe {
            asm!(r#" /* Load GDT */

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

impl Drop for GDT {
    fn drop(&mut self) {
        // Check to see whether the GDT being dropped is the one currently
        // loaded on this CPU.  If so, reload the global GDT.
        let gdt_desc: GDTDesc = Default::default();
        // SAFETY: assembly is required to obtain the current GDT descriptor.
        // The address of the returned descriptor is only used as a comparison
        // to `self` and not for data access, so memory safety is not affected
        // by the returned address.
        unsafe {
            asm!("sgdt ({0})",
                 in(reg) &gdt_desc,
                 options(att_syntax));
        }

        let gdt_addr = gdt_desc.addr;
        if gdt_addr == VirtAddr::from(self as *const GDT) {
            GLOBAL_GDT.load();
        }
    }
}
