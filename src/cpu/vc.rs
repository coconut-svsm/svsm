// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::idt::common::X86ExceptionContext;
use crate::cpu::cpuid::{cpuid_table_raw, CpuidLeaf};
use crate::cpu::extable::handle_exception_table;
use crate::cpu::insn::{insn_fetch, Instruction};
use crate::cpu::registers::X86GeneralRegs;
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

    match err {
        // If the debugger is enabled then handle the DB exception
        // by directly invoking the exception handler
        X86_TRAP_DB => {
            handle_db_exception(ctx);
            Ok(())
        }

        SVM_EXIT_CPUID => handle_cpuid(ctx),
        _ => Err(SvsmError::Vc(VcError::Unsupported)),
    }
    .unwrap_or_else(|error| {
        panic!(
            "Unhandled #VC exception RIP {:#018x} error code: {:#018x}: error: {:?}",
            rip, err, error
        )
    });

    vc_finish_insn(ctx);
}

fn handle_cpuid(ctx: &mut X86ExceptionContext) -> Result<(), SvsmError> {
    let regs = &mut ctx.regs;

    /*
     * Section 2.3.1 GHCB MSR Protocol in SEV-ES Guest-Hypervisor Communication Block
     * Standardization Rev. 2.02.
     * For SEV-ES/SEV-SNP, we can use the CPUID table already defined and populated with
     * firmware information.
     * We choose for now not to call the hypervisor to perform CPUID, since it's no trusted.
     * Since GHCB is not needed to handle CPUID with the firmware table, we can call the handler
     * very soon in stage 2.
     */

    snp_cpuid(regs)
}

fn snp_cpuid(regs: &mut X86GeneralRegs) -> Result<(), SvsmError> {
    let mut leaf = CpuidLeaf::new(regs.rax as u32, regs.rcx as u32);

    let ret = match cpuid_table_raw(leaf.cpuid_fn, leaf.cpuid_subfn, 0, 0) {
        None => Err(SvsmError::Vc(VcError::UnknownCpuidLeaf)),
        Some(v) => Ok(v),
    }?;

    leaf.eax = ret.eax;
    leaf.ebx = ret.ebx;
    leaf.ecx = ret.ecx;
    leaf.edx = ret.edx;

    regs.rax = leaf.eax as usize;
    regs.rbx = leaf.ebx as usize;
    regs.rcx = leaf.ecx as usize;
    regs.rdx = leaf.edx as usize;

    Ok(())
}

fn vc_finish_insn(ctx: &mut X86ExceptionContext) {
    ctx.frame.rip += ctx.insn.length;
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
