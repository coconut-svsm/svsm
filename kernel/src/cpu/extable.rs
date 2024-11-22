// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern "C" {
    pub static exception_table_start: u8;
    pub static exception_table_end: u8;
}

use super::idt::common::X86ExceptionContext;
use crate::address::{Address, VirtAddr};
use core::mem;

#[repr(C, packed)]
struct ExceptionTableEntry {
    start: VirtAddr,
    end: VirtAddr,
}

fn check_exception_table(rip: VirtAddr) -> VirtAddr {
    let ex_table_start = VirtAddr::from(&raw const exception_table_start);
    let ex_table_end = VirtAddr::from(&raw const exception_table_end);
    let mut current = ex_table_start;

    loop {
        // SAFETY: `current` is guaranteed to be a valid address within the
        // exception table.
        let addr = unsafe { &*current.as_ptr::<ExceptionTableEntry>() };

        let start = addr.start;
        let end = addr.end;

        if rip >= start && rip < end {
            return end;
        }

        current = current + mem::size_of::<ExceptionTableEntry>();
        if current >= ex_table_end {
            break;
        }
    }

    rip
}

pub fn dump_exception_table() {
    let ex_table_start = VirtAddr::from(&raw const exception_table_start);
    let ex_table_end = VirtAddr::from(&raw const exception_table_end);
    let mut current = ex_table_start;

    loop {
        // SAFETY: `current` is guaranteed to be a valid address within the
        // exception table.
        let addr = unsafe { &*current.as_ptr::<ExceptionTableEntry>() };

        let start = addr.start;
        let end = addr.end;

        log::info!("Extable Entry {:#018x}-{:#018x}", start, end);

        current = current + mem::size_of::<ExceptionTableEntry>();
        if current >= ex_table_end {
            break;
        }
    }
}

pub fn handle_exception_table(ctx: &mut X86ExceptionContext) -> bool {
    let ex_rip = VirtAddr::from(ctx.frame.rip);
    let new_rip = check_exception_table(ex_rip);

    // If an exception hit in an area covered by the exception table, set rcx to -1
    if new_rip != ex_rip {
        ctx.regs.rcx = !0usize;
        ctx.set_rip(new_rip.bits());
        return true;
    }

    false
}
