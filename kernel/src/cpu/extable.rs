// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::idt::common::X86ExceptionContext;
use crate::address::{Address, VirtAddr};
use crate::utils::MemoryRegion;
use core::mem;

extern "C" {
    static exception_table_start: u8;
    static exception_table_end: u8;
    static early_exception_table_start: u8;
    static early_exception_table_end: u8;
}

#[repr(C, packed)]
struct ExceptionTableEntry {
    start: VirtAddr,
    end: VirtAddr,
}

fn check_exception_table(rip: VirtAddr, ex_table: MemoryRegion<VirtAddr>) -> VirtAddr {
    let mut current = ex_table.start();
    let ex_table_end = ex_table.end();

    loop {
        // SAFETY: `current` is guaranteed to be a valid address within the
        // exception table.
        let addr = unsafe { &*current.as_ptr::<ExceptionTableEntry>() };

        let start = addr.start;
        let end = addr.end;

        if (start..end).contains(&rip) {
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
        let entry = MemoryRegion::from_addresses(addr.start, addr.end);

        log::info!("Extable Entry {entry:#018x}");

        current = current + mem::size_of::<ExceptionTableEntry>();
        if current >= ex_table_end {
            break;
        }
    }
}

fn handle_exception_table_common(
    ctx: &mut X86ExceptionContext,
    ex_table: MemoryRegion<VirtAddr>,
) -> bool {
    let ex_rip = VirtAddr::from(ctx.frame.rip);
    let new_rip = check_exception_table(ex_rip, ex_table);

    // If an exception hit in an area covered by the exception table, set rcx to -1
    if new_rip != ex_rip {
        ctx.regs.rcx = !0usize;
        // SAFETY: check_exception_table() returns a valid RIP from the
        // exception table
        unsafe {
            ctx.set_rip(new_rip.bits());
        }
        true
    } else {
        false
    }
}

pub fn handle_exception_table_early(ctx: &mut X86ExceptionContext) -> bool {
    let ex_table = MemoryRegion::from_addresses(
        VirtAddr::from(&raw const early_exception_table_start),
        VirtAddr::from(&raw const early_exception_table_end),
    );
    handle_exception_table_common(ctx, ex_table)
}

pub fn handle_exception_table(ctx: &mut X86ExceptionContext) -> bool {
    let ex_table = MemoryRegion::from_addresses(
        VirtAddr::from(&raw const exception_table_start),
        VirtAddr::from(&raw const exception_table_end),
    );
    handle_exception_table_common(ctx, ex_table)
}
