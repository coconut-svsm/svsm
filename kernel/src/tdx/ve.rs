// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::tdcall::{tdcall_get_ve_info, tdvmcall_cpuid};
use super::TdxError;
use crate::cpu::idt::common::X86ExceptionContext;
use crate::error::SvsmError;

const VMX_EXIT_REASON_CPUID: u32 = 10;

pub fn handle_virtualization_exception(ctx: &mut X86ExceptionContext) -> Result<(), SvsmError> {
    let veinfo = tdcall_get_ve_info().expect("Failed to get #VE info");

    match veinfo.exit_reason {
        VMX_EXIT_REASON_CPUID => handle_cpuid(ctx),
        _ => Err(TdxError::Unknown(veinfo.exit_reason.into()).into()),
    }?;

    let new_rip = ctx.frame.rip + veinfo.exit_instruction_length as usize;
    // SAFETY: we are advancing the instruction pointer by the size of the exit
    // instruction.
    unsafe {
        ctx.set_rip(new_rip);
    }
    Ok(())
}

fn handle_cpuid(ctx: &mut X86ExceptionContext) -> Result<(), SvsmError> {
    let cpuidinfo = tdvmcall_cpuid(ctx.regs.rax as u32, ctx.regs.rcx as u32);
    ctx.regs.rax = cpuidinfo.eax as usize;
    ctx.regs.rbx = cpuidinfo.ebx as usize;
    ctx.regs.rcx = cpuidinfo.ecx as usize;
    ctx.regs.rdx = cpuidinfo.edx as usize;
    Ok(())
}
