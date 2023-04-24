// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern "C" {
    pub static exception_table_start: u8;
    pub static exception_table_end: u8;
}

use crate::address::{Address, VirtAddr};
use crate::cpu::X86Regs;
use core::mem;

#[repr(C, packed)]
struct ExceptionTableEntry {
    start: VirtAddr,
    end: VirtAddr,
}

fn check_exception_table(rip: VirtAddr) -> VirtAddr {
    unsafe {
        let ex_table_start = VirtAddr::from(&exception_table_start as *const u8);
        let ex_table_end = VirtAddr::from(&exception_table_end as *const u8);
        let mut current = ex_table_start;

        loop {
            let addr = current.as_ptr::<ExceptionTableEntry>();

            let start = (*addr).start;
            let end = (*addr).end;

            if rip >= start && rip < end {
                return end;
            }

            current = current.offset(mem::size_of::<ExceptionTableEntry>());
            if current >= ex_table_end {
                break;
            }
        }
    }

    return rip;
}

pub fn dump_exception_table() {
    unsafe {
        let ex_table_start = VirtAddr::from(&exception_table_start as *const u8);
        let ex_table_end = VirtAddr::from(&exception_table_end as *const u8);
        let mut current = ex_table_start;

        loop {
            let addr = current.as_ptr::<ExceptionTableEntry>();

            let start = (*addr).start;
            let end = (*addr).end;

            log::info!("Extable Entry {:#018x}-{:#018x}", start, end);

            current = current.offset(mem::size_of::<ExceptionTableEntry>());
            if current >= ex_table_end {
                break;
            }
        }
    }
}

pub fn handle_exception_table(regs: &mut X86Regs) -> bool {
    let ex_rip = VirtAddr::from(regs.rip);
    let new_rip = check_exception_table(ex_rip);

    // If an exception hit in an area covered by the exception table, set rcx to -1
    if new_rip != ex_rip {
        regs.rcx = !0usize;
        regs.rip = new_rip.bits();
        return true;
    }

    return false;
}
