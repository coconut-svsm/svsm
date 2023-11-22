// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::tss::{X86Tss, TSS_LIMIT};
use crate::address::VirtAddr;
use crate::types::{SVSM_CS, SVSM_DS, SVSM_TSS};
use core::arch::asm;
use core::mem;

#[repr(C, packed(2))]
#[derive(Clone, Copy, Debug)]
pub struct GdtDesc {
    size: u16,
    addr: VirtAddr,
}

const GDT_SIZE: u16 = 8;

static mut GDT: [u64; GDT_SIZE as usize] = [
    0,
    0x00af9a000000ffff, // 64-bit CPL=0 code segment
    0x00cf92000000ffff, // 64-bit CPL=0 data segment
    // The layout of the CPL-3 entries is dictated by the requirements of
    // the STAR MSR (C000_0081h). See 6.1.1 in the AMD64 Architecture
    // Programmer's Manual Volume 2.
    0,                  // 32-bit CPL=3 code (unused)
    0x00cff2000000ffff, // 64-bit CPL=3 data segment
    0x00affa000000ffff, // 64-bit CPL=3 code segment
    0,                  // TSS
    0,                  // TSS continued
];

pub fn load_tss(tss: &X86Tss) {
    let addr = (tss as *const X86Tss) as u64;

    let mut desc0: u64 = 0;
    let mut desc1: u64 = 0;

    // Limit
    desc0 |= TSS_LIMIT & 0xffffu64;
    desc0 |= ((TSS_LIMIT >> 16) & 0xfu64) << 48;

    // Address
    desc0 |= (addr & 0x00ff_ffffu64) << 16;
    desc0 |= (addr & 0xff00_0000u64) << 32;
    desc1 |= addr >> 32;

    // Present
    desc0 |= 1u64 << 47;

    // Type
    desc0 |= 0x9u64 << 40;

    unsafe {
        let idx = (SVSM_TSS / 8) as usize;
        GDT[idx] = desc0;
        GDT[idx + 1] = desc1;

        asm!("ltr %ax", in("ax") SVSM_TSS, options(att_syntax));
    }
}

pub fn gdt_base_limit() -> (u64, u32) {
    unsafe {
        let gdt_entries = GDT_SIZE as usize;
        let base = (&GDT as *const [u64; GDT_SIZE as usize]) as u64;
        let limit = ((mem::size_of::<u64>() * gdt_entries) - 1) as u32;
        (base, limit)
    }
}

pub fn load_gdt() {
    unsafe {
        let gdt_desc: GdtDesc = GdtDesc {
            size: (GDT_SIZE * 8) - 1,
            addr: VirtAddr::from(GDT.as_ptr()),
        };

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
