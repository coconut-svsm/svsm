// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use super::{tdcall, TdxError};
use crate::cpu::idt::common::X86ExceptionContext;
use crate::cpu::x86::apic::MSR_APIC_BASE;
use crate::error::SvsmError;

const VMX_EXIT_REASON_CPUID: u32 = 10;
const VMX_EXIT_REASON_RDMSR: u32 = 31;
const VMX_EXIT_REASON_WRMSR: u32 = 32;

pub fn handle_virtualization_exception(ctx: &mut X86ExceptionContext) -> Result<(), SvsmError> {
    let veinfo = tdcall::tdcall_get_ve_info().expect("Failed to get #VE info");

    match veinfo.exit_reason {
        VMX_EXIT_REASON_CPUID => handle_cpuid(ctx),
        VMX_EXIT_REASON_RDMSR => handle_rdmsr(ctx),
        VMX_EXIT_REASON_WRMSR => handle_wrmsr(ctx),
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
    let cpuidinfo = tdcall::tdvmcall_cpuid(ctx.regs.rax as u32, ctx.regs.rcx as u32);
    ctx.regs.rax = cpuidinfo.eax as usize;
    ctx.regs.rbx = cpuidinfo.ebx as usize;
    ctx.regs.rcx = cpuidinfo.ecx as usize;
    ctx.regs.rdx = cpuidinfo.edx as usize;
    Ok(())
}

fn handle_rdmsr(ctx: &mut X86ExceptionContext) -> Result<(), SvsmError> {
    let msr = ctx.regs.rcx as u32;
    match msr {
        MSR_APIC_BASE => (),
        0x800..=0x8FF => (),
        _ => return Err(TdxError::Unimplemented.into()),
    }
    let val = tdcall::tdvmcall_rdmsr(msr);
    ctx.regs.rax = (val as u32) as usize;
    ctx.regs.rdx = (val >> 32) as usize;
    Ok(())
}

fn handle_wrmsr(ctx: &X86ExceptionContext) -> Result<(), SvsmError> {
    let msr = ctx.regs.rcx as u32;
    match msr {
        MSR_APIC_BASE => (),
        0x800..=0x8FF => (),
        _ => return Err(TdxError::Unimplemented.into()),
    }
    let val = u64::from(ctx.regs.rax as u32) | ((ctx.regs.rdx as u64) << 32);
    tdcall::tdvmcall_wrmsr(msr, val);
    Ok(())
}
