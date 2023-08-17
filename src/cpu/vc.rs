// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::idt::common::X86ExceptionContext;
use crate::cpu::extable::handle_exception_table;
use crate::cpu::insn::{insn_fetch, Instruction};
use crate::debug::gdbstub::svsm_gdbstub::handle_db_exception;
use crate::error::SvsmError;

use core::fmt;

pub const SVM_EXIT_EXCP_BASE: usize = 0x40;
pub const SVM_EXIT_LAST_EXCP: usize = 0x5f;
pub const SVM_EXIT_CPUID: usize = 0x72;
pub const X86_TRAP_DB: usize = 0x01;
pub const X86_TRAP: usize = SVM_EXIT_EXCP_BASE + X86_TRAP_DB;

#[derive(Clone, Copy, Debug)]
pub enum VcError {
    Unsupported,
    DecodeFailed,
    UnknownCpuidLeaf,
}

impl From<VcError> for SvsmError {
    fn from(e: VcError) -> Self {
        Self::Vc(e)
    }
}

impl fmt::Display for VcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Unsupported => {
                write!(f, "unsupported #VC exception")
            }
            Self::DecodeFailed => {
                write!(f, "invalid instruction")
            }
            Self::UnknownCpuidLeaf => {
                write!(f, "unknown CPUID leaf")
            }
        }
    }
}

pub fn stage2_handle_vc_exception(ctx: &mut X86ExceptionContext) {
    let err = ctx.error_code;
    let rip = ctx.frame.rip;

    vc_decode_insn(ctx).unwrap_or_else(|e| {
        panic!(
            "Unhandled #VC exception RIP {:#018x} error code: {:#018x} error {:?}",
            rip, err, e
        )
    });

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

fn vc_decode_insn(ctx: &mut X86ExceptionContext) -> Result<(), SvsmError> {
    if !vc_decoding_needed(ctx.error_code) {
        return Ok(());
    }

    // TODO: the instruction fetch will likely to be handled differently when
    // #VC exception will be raised from CPL > 0.
    // TODO: handle invalid RIPs with exception fixup
    // SAFETY: safe if [rip;rip+MAX_INSN_SIZE] doesn't overlap with an unmapped page
    let insn_raw = unsafe { insn_fetch(ctx.frame.rip as *const u8) };

    let mut insn = Instruction::new(insn_raw);
    insn.decode()?;

    ctx.insn = insn;

    Ok(())
}

fn vc_decoding_needed(error_code: usize) -> bool {
    !(SVM_EXIT_EXCP_BASE..=SVM_EXIT_LAST_EXCP).contains(&error_code)
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
