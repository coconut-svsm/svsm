// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Authors: Joerg Roedel <jroedel@suse.de>

use super::super::control_regs::read_cr2;
use super::super::extable::handle_exception_table;
use super::super::percpu::this_cpu;
use super::super::tss::IST_DF;
use super::super::vc::handle_vc_exception;
use super::common::PF_ERROR_WRITE;
use super::common::{
    idt_mut, IdtEntry, AC_VECTOR, BP_VECTOR, BR_VECTOR, CP_VECTOR, DB_VECTOR, DE_VECTOR, DF_VECTOR,
    GP_VECTOR, HV_VECTOR, MCE_VECTOR, MF_VECTOR, NMI_VECTOR, NM_VECTOR, NP_VECTOR, OF_VECTOR,
    PF_VECTOR, SS_VECTOR, SX_VECTOR, TS_VECTOR, UD_VECTOR, VC_VECTOR, XF_VECTOR,
};
use crate::address::VirtAddr;
use crate::cpu::X86ExceptionContext;
use crate::debug::gdbstub::svsm_gdbstub::handle_debug_exception;
use core::arch::global_asm;

extern "C" {
    fn asm_entry_de();
    fn asm_entry_db();
    fn asm_entry_nmi();
    fn asm_entry_bp();
    fn asm_entry_of();
    fn asm_entry_br();
    fn asm_entry_ud();
    fn asm_entry_nm();
    fn asm_entry_df();
    fn asm_entry_ts();
    fn asm_entry_np();
    fn asm_entry_ss();
    fn asm_entry_gp();
    fn asm_entry_pf();
    fn asm_entry_mf();
    fn asm_entry_ac();
    fn asm_entry_mce();
    fn asm_entry_xf();
    fn asm_entry_cp();
    fn asm_entry_hv();
    fn asm_entry_vc();
    fn asm_entry_sx();
}

fn init_ist_vectors() {
    idt_mut().set_entry(
        DF_VECTOR,
        IdtEntry::ist_entry(asm_entry_df, IST_DF.try_into().unwrap()),
    );
}

pub fn early_idt_init() {
    let mut idt = idt_mut();
    idt.set_entry(DE_VECTOR, IdtEntry::entry(asm_entry_de));
    idt.set_entry(DB_VECTOR, IdtEntry::entry(asm_entry_db));
    idt.set_entry(NMI_VECTOR, IdtEntry::entry(asm_entry_nmi));
    idt.set_entry(BP_VECTOR, IdtEntry::entry(asm_entry_bp));
    idt.set_entry(OF_VECTOR, IdtEntry::entry(asm_entry_of));
    idt.set_entry(BR_VECTOR, IdtEntry::entry(asm_entry_br));
    idt.set_entry(UD_VECTOR, IdtEntry::entry(asm_entry_ud));
    idt.set_entry(NM_VECTOR, IdtEntry::entry(asm_entry_nm));
    idt.set_entry(DF_VECTOR, IdtEntry::entry(asm_entry_df));
    idt.set_entry(TS_VECTOR, IdtEntry::entry(asm_entry_ts));
    idt.set_entry(NP_VECTOR, IdtEntry::entry(asm_entry_np));
    idt.set_entry(SS_VECTOR, IdtEntry::entry(asm_entry_ss));
    idt.set_entry(GP_VECTOR, IdtEntry::entry(asm_entry_gp));
    idt.set_entry(PF_VECTOR, IdtEntry::entry(asm_entry_pf));
    idt.set_entry(MF_VECTOR, IdtEntry::entry(asm_entry_mf));
    idt.set_entry(AC_VECTOR, IdtEntry::entry(asm_entry_ac));
    idt.set_entry(MCE_VECTOR, IdtEntry::entry(asm_entry_mce));
    idt.set_entry(XF_VECTOR, IdtEntry::entry(asm_entry_xf));
    idt.set_entry(CP_VECTOR, IdtEntry::entry(asm_entry_cp));
    idt.set_entry(HV_VECTOR, IdtEntry::entry(asm_entry_hv));
    idt.set_entry(VC_VECTOR, IdtEntry::entry(asm_entry_vc));
    idt.set_entry(SX_VECTOR, IdtEntry::entry(asm_entry_sx));
    idt.load();
}

pub fn idt_init() {
    // Set IST vectors
    init_ist_vectors();
}

// Debug handler
#[no_mangle]
extern "C" fn ex_handler_debug(ctx: &mut X86ExceptionContext) {
    handle_debug_exception(ctx, DB_VECTOR);
}

// Breakpoint handler
#[no_mangle]
extern "C" fn ex_handler_breakpoint(ctx: &mut X86ExceptionContext) {
    handle_debug_exception(ctx, BP_VECTOR);
}

// Doube-Fault handler
#[no_mangle]
extern "C" fn ex_handler_double_fault(ctx: &mut X86ExceptionContext) {
    let cr2 = read_cr2();
    let rip = ctx.frame.rip;
    let rsp = ctx.frame.rsp;
    panic!(
        "Double-Fault at RIP {:#018x} RSP: {:#018x} CR2: {:#018x}",
        rip, rsp, cr2
    );
}

// General-Protection handler
#[no_mangle]
extern "C" fn ex_handler_general_protection(ctx: &mut X86ExceptionContext) {
    let rip = ctx.frame.rip;
    let err = ctx.error_code;

    if !handle_exception_table(ctx) {
        panic!(
            "Unhandled General-Protection-Fault at RIP {:#018x} error code: {:#018x}",
            rip, err
        );
    }
}

// Page-Fault handler
#[no_mangle]
extern "C" fn ex_handler_page_fault(ctx: &mut X86ExceptionContext) {
    let cr2 = read_cr2();
    let rip = ctx.frame.rip;
    let err = ctx.error_code;

    if this_cpu()
        .handle_pf(VirtAddr::from(cr2), (err & PF_ERROR_WRITE) != 0)
        .is_err()
        && !handle_exception_table(ctx)
    {
        handle_debug_exception(ctx, ctx.vector);
        panic!(
            "Unhandled Page-Fault at RIP {:#018x} CR2: {:#018x} error code: {:#018x}",
            rip, cr2, err
        );
    }
}

// Hypervisor Injection handler
#[no_mangle]
extern "C" fn ex_handler_hypervisor_injection(_ctx: &mut X86ExceptionContext) {
    // #HV processing is not required in the SVSM.  If a maskable
    // interrupt occurs, it will be processed prior to the next exit.
    // There are no NMI sources, and #MC cannot be handled anyway
    // and can safely be ignored.
}

// VMM Communication handler
#[no_mangle]
extern "C" fn ex_handler_vmm_communication(ctx: &mut X86ExceptionContext) {
    handle_vc_exception(ctx);
}

#[no_mangle]
pub extern "C" fn ex_handler_panic(ctx: &mut X86ExceptionContext) {
    let vec = ctx.vector;
    let rip = ctx.frame.rip;
    let err = ctx.error_code;
    panic!(
        "Unhandled exception {} RIP {:#018x} error code: {:#018x}",
        vec, rip, err
    );
}

global_asm!(include_str!("entry.S"), options(att_syntax));
