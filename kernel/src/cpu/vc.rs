// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::idt::common::X86ExceptionContext;
use crate::address::VirtAddr;
use crate::cpu::cpuid::{cpuid_table_raw, CpuidLeaf};
use crate::cpu::ghcb::current_ghcb;
use crate::cpu::insn::{insn_fetch, Instruction};
use crate::cpu::percpu::this_cpu;
use crate::cpu::registers::from_user;
use crate::debug::gdbstub::svsm_gdbstub::handle_debug_exception;
use crate::error::SvsmError;
use crate::sev::ghcb::{GHCBIOSize, GHCB};
use crate::utils::align_down;
use core::mem::size_of;
use core::{fmt, ptr};

pub const SVM_EXIT_EXCP_BASE: usize = 0x40;
pub const SVM_EXIT_LAST_EXCP: usize = 0x5f;
pub const SVM_EXIT_CPUID: usize = 0x72;
pub const SVM_EXIT_IOIO: usize = 0x7b;
pub const X86_TRAP_DB: usize = 0x01;
pub const X86_TRAP: usize = SVM_EXIT_EXCP_BASE + X86_TRAP_DB;

#[derive(Clone, Copy, Debug)]
pub struct VcError {
    pub rip: usize,
    pub code: usize,
    pub error_type: VcErrorType,
}

#[derive(Clone, Copy, Debug)]
pub enum VcErrorType {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unhandled #VC exception ")?;
        match self.error_type {
            VcErrorType::Unsupported => {
                write!(f, "unsupported #VC exception")?;
            }
            VcErrorType::DecodeFailed => {
                write!(f, "invalid instruction")?;
            }
            VcErrorType::UnknownCpuidLeaf => {
                write!(f, "unknown CPUID leaf")?;
            }
        }
        write!(
            f,
            " RIP: {:#018x}: error code: {:#018x}",
            self.rip, self.code
        )
    }
}

pub fn stage2_handle_vc_exception_no_ghcb(ctx: &mut X86ExceptionContext) {
    let err = ctx.error_code;
    let rip = ctx.frame.rip;

    let insn = vc_decode_insn(ctx).expect("Could not decode instructions");

    match err {
        SVM_EXIT_CPUID => handle_cpuid(ctx).expect("Could not handle CPUID #VC exception"),
        _ => {
            panic!(
                "Unsupported #VC exception RIP {:#018x} error code: {:#018x}",
                rip, err,
            )
        }
    }

    vc_finish_insn(ctx, &insn);
}

pub fn stage2_handle_vc_exception(ctx: &mut X86ExceptionContext) {
    let err = ctx.error_code;
    let rip = ctx.frame.rip;

    // To handle NAE events, we're supposed to reset the VALID_BITMAP field of the GHCB.
    // This is currently only relevant for IOIO handling. This field is currently reset in
    // the ioio_{in,ou} methods but it would be better to move the reset out of the different
    // handlers.
    let mut ghcb = current_ghcb();

    let insn = vc_decode_insn(ctx).expect("Could not decode instructions");

    match err {
        SVM_EXIT_CPUID => handle_cpuid(ctx).expect("Could not handle CPUID #VC exception"),
        SVM_EXIT_IOIO => {
            handle_ioio(ctx, &mut ghcb, &insn).expect("Could not handle IOIO #VC exception")
        }
        _ => {
            panic!(
                "Unsupported #VC exception RIP {:#018x} error code: {:#018x}",
                rip, err
            );
        }
    }

    vc_finish_insn(ctx, &insn);
}

pub fn handle_vc_exception(ctx: &mut X86ExceptionContext) {
    let error_code = ctx.error_code;
    let rip = ctx.frame.rip;

    // To handle NAE events, we're supposed to reset the VALID_BITMAP field of the GHCB.
    // This is currently only relevant for IOIO handling. This field is currently reset in
    // the ioio_{in,ou} methods but it would be better to move the reset out of the different
    // handlers.
    let mut ghcb = current_ghcb();

    let insn = vc_decode_insn(ctx).expect("Could not decode instruction");

    match error_code {
        // If the gdb stub is enabled then debugging operations such as single stepping
        // will cause either an exception via DB_VECTOR if the DEBUG_SWAP sev_feature is
        // clear, or a VC exception with an error code of X86_TRAP if set.
        X86_TRAP => handle_debug_exception(ctx, ctx.vector),
        SVM_EXIT_CPUID => handle_cpuid(ctx).expect("Could not handle CPUID #VC exception"),
        SVM_EXIT_IOIO => {
            handle_ioio(ctx, &mut ghcb, &insn).expect("Could not handle IOIO #VC exception")
        }
        _ => {
            panic!(
                "Unsupported #VC exception RIP {:#018x} error code: {:#018x}",
                rip, error_code
            )
        }
    }

    vc_finish_insn(ctx, &insn);
}

fn handle_cpuid(ctx: &mut X86ExceptionContext) -> Result<(), SvsmError> {
    // Section 2.3.1 GHCB MSR Protocol in SEV-ES Guest-Hypervisor Communication Block
    // Standardization Rev. 2.02.
    // For SEV-ES/SEV-SNP, we can use the CPUID table already defined and populated with
    // firmware information.
    // We choose for now not to call the hypervisor to perform CPUID, since it's no trusted.
    // Since GHCB is not needed to handle CPUID with the firmware table, we can call the handler
    // very soon in stage 2.

    snp_cpuid(ctx)
}

fn snp_cpuid(ctx: &mut X86ExceptionContext) -> Result<(), SvsmError> {
    let mut leaf = CpuidLeaf::new(ctx.regs.rax as u32, ctx.regs.rcx as u32);

    let Some(ret) = cpuid_table_raw(leaf.cpuid_fn, leaf.cpuid_subfn, 0, 0) else {
        return Err(SvsmError::Vc(VcError {
            rip: ctx.frame.rip,
            code: ctx.error_code,
            error_type: VcErrorType::UnknownCpuidLeaf,
        }));
    };

    leaf.eax = ret.eax;
    leaf.ebx = ret.ebx;
    leaf.ecx = ret.ecx;
    leaf.edx = ret.edx;

    ctx.regs.rax = leaf.eax as usize;
    ctx.regs.rbx = leaf.ebx as usize;
    ctx.regs.rcx = leaf.ecx as usize;
    ctx.regs.rdx = leaf.edx as usize;

    Ok(())
}

fn vc_finish_insn(ctx: &mut X86ExceptionContext, insn: &Instruction) {
    ctx.frame.rip += insn.len()
}

fn handle_ioio(
    ctx: &mut X86ExceptionContext,
    ghcb: &mut GHCB,
    insn: &Instruction,
) -> Result<(), SvsmError> {
    let port: u16 = (ctx.regs.rdx & 0xffff) as u16;
    let out_value: u64 = ctx.regs.rax as u64;

    match insn.opcode[0] {
        0x6C..=0x6F | 0xE4..=0xE7 => Err(SvsmError::Vc(VcError {
            rip: ctx.frame.rip,
            code: ctx.error_code,
            error_type: VcErrorType::Unsupported,
        })),
        0xEC => {
            let ret = ghcb.ioio_in(port, GHCBIOSize::Size8)?;
            ctx.regs.rax = (ret & 0xff) as usize;
            Ok(())
        }
        0xED => {
            let (size, mask) = match insn.prefixes {
                Some(prefix) if prefix.nb_bytes > 0 => (GHCBIOSize::Size16, u16::MAX as u64),
                _ => (GHCBIOSize::Size32, u32::MAX as u64),
            };

            let ret = ghcb.ioio_in(port, size)?;
            ctx.regs.rax = (ret & mask) as usize;
            Ok(())
        }
        0xEE => ghcb.ioio_out(port, GHCBIOSize::Size8, out_value),
        0xEF => {
            let mut size: GHCBIOSize = GHCBIOSize::Size32;
            if let Some(prefix) = insn.prefixes {
                // this is always true at the moment
                if prefix.nb_bytes > 0 {
                    // outw instruction has a 0x66 operand-size prefix for word-sized operands.
                    size = GHCBIOSize::Size16;
                }
            }

            ghcb.ioio_out(port, size, out_value)
        }
        _ => Err(SvsmError::Vc(VcError {
            rip: ctx.frame.rip,
            code: ctx.error_code,
            error_type: VcErrorType::DecodeFailed,
        })),
    }
}

fn vc_decode_insn(ctx: &mut X86ExceptionContext) -> Result<Instruction, SvsmError> {
    if !vc_decoding_needed(ctx.error_code) {
        return Ok(Instruction::default());
    }

    // TODO: the instruction fetch will likely to be handled differently when
    // #VC exception will be raised from CPL > 0.
    // TODO: handle invalid RIPs with exception fixup
    // SAFETY: safe if [rip;rip+MAX_INSN_SIZE] doesn't overlap with an unmapped page
    let insn_raw = unsafe { insn_fetch(ctx.frame.rip as *const u8) };

    let mut insn = Instruction::new(insn_raw);
    insn.decode()?;

    Ok(insn)
}

fn vc_decoding_needed(error_code: usize) -> bool {
    !(SVM_EXIT_EXCP_BASE..=SVM_EXIT_LAST_EXCP).contains(&error_code)
}

/// Used to move to a safe stack if #VC is a nested one or raised from user-mode.
///
/// # Arguments:
///
/// - `ctx`: registers from the exception raising context that have been pushed on the initial
/// handler stack at the early handling stage.
///
/// # Returns:
///
/// [`VirtAddr`]: the new stack address. This address is directly moved to RSP in the caller.
/// Therefore, the new address should absolutely be valid.
#[no_mangle]
extern "C" fn vc_switch_off_ist(ctx: &X86ExceptionContext) -> VirtAddr {
    // Detect user #VC or nested IST #VC
    let mut new_rsp = if from_user(ctx) || vc_on_ist_stack(ctx) {
        this_cpu().current_stack.end()
    } else {
        VirtAddr::from(ctx.frame.rsp)
    };

    new_rsp =
        VirtAddr::from(align_down(usize::from(new_rsp), 8) - size_of::<X86ExceptionContext>());

    // Copy the x86 exception context to the new stack
    // Safety: ctx content is user-controlled but its size is fixed.
    // dst is not controllable by user. new_rsp can only be on current task's stack.
    // dst is also properly aligned by the code above.
    unsafe { ptr::write::<X86ExceptionContext>(new_rsp.as_mut_ptr(), *ctx) }

    new_rsp
}

fn vc_on_ist_stack(ctx: &X86ExceptionContext) -> bool {
    this_cpu()
        .get_vc_stack_bounds()
        .unwrap()
        .contains(VirtAddr::from(ctx.frame.rsp))
}
