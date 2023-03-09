// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

extern "C" {
    pub static exception_table_start: u8;
    pub static exception_table_end: u8;
}

use crate::cpu::X86Regs;
use crate::types::VirtAddr;
use core::mem;

#[repr(C, packed)]
struct ExceptionTableEntry {
    start: usize,
    end: usize,
}

fn check_exception_table(rip: usize) -> usize {
    unsafe {
        let ex_table_start: VirtAddr = (&exception_table_start as *const u8) as VirtAddr;
        let ex_table_end: VirtAddr = (&exception_table_end as *const u8) as VirtAddr;
        let mut current = ex_table_start;

        loop {
            let addr = current as *const ExceptionTableEntry;

            let start = (*addr).start;
            let end = (*addr).end;

            if rip >= start && rip < end {
                return end;
            }

            current += mem::size_of::<ExceptionTableEntry>();
            if current >= ex_table_end {
                break;
            }
        }
    }

    return rip;
}

pub fn dump_exception_table() {
    unsafe {
        let ex_table_start: VirtAddr = (&exception_table_start as *const u8) as VirtAddr;
        let ex_table_end: VirtAddr = (&exception_table_end as *const u8) as VirtAddr;
        let mut current = ex_table_start;

        loop {
            let addr = current as *const ExceptionTableEntry;

            let start = (*addr).start;
            let end = (*addr).end;

            log::info!("Extable Entry {:#018x}-{:#018x}", start, end);

            current += mem::size_of::<ExceptionTableEntry>();
            if current >= ex_table_end {
                break;
            }
        }
    }
}

pub fn handle_exception_table(regs: &mut X86Regs) -> bool {
    let ex_rip = regs.rip;
    let new_rip = check_exception_table(ex_rip);

    // If an exception hit in an area covered by the exception table, set rcx to -1
    if new_rip != ex_rip {
        regs.rcx = !0usize;
        regs.rip = new_rip;
        return true;
    }

    return false;
}
