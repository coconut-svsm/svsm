// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::idt::common::X86ExceptionContext;
use crate::cpu::extable::handle_exception_table;
use crate::debug::gdbstub::svsm_gdbstub::handle_db_exception;

pub const SVM_EXIT_EXCP_BASE: usize = 0x40;
pub const X86_TRAP_DB: usize = 0x01;

pub fn stage2_handle_vc_exception(ctx: &mut X86ExceptionContext) {
    let err = ctx.error_code;
    let rip = ctx.frame.rip;

    // If the debugger is enabled then handle the DB exception
    // by directly invoking the exception hander
    if err == (SVM_EXIT_EXCP_BASE + X86_TRAP_DB) {
        handle_db_exception(ctx);
        return;
    }

    panic!(
        "Unhandled #VC exception RIP {:#018x} error code: {:#018x}",
        rip, err
    );
}

pub fn handle_vc_exception(ctx: &mut X86ExceptionContext) {
    let err = ctx.error_code;
    let rip = ctx.frame.rip;

    // If the debugger is enabled then handle the DB exception
    // by directly invoking the exception hander
    if err == (SVM_EXIT_EXCP_BASE + X86_TRAP_DB) {
        handle_db_exception(ctx);
        return;
    }

    if !handle_exception_table(ctx) {
        panic!(
            "Unhandled #VC exception RIP {:#018x} error code: {:#018x}",
            rip, err
        );
    }
}
