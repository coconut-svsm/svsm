// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::super::tss::IST_DF;
use super::common::{
    load_idt, Idt, IdtEntry, X86Regs, BP_VECTOR, DF_VECTOR, GLOBAL_IDT, SVM_EXIT_EXCP_BASE,
    VC_VECTOR, X86_TRAP_DB,
};
use crate::address::VirtAddr;
use crate::cpu::control_regs::read_cr2;
use crate::debug::gdbstub::svsm_gdbstub::{handle_bp_exception, handle_db_exception};
use core::arch::global_asm;

fn init_idt(idt: &mut Idt) {
    // Set IDT handlers
    let handlers = unsafe { VirtAddr::from(&stage2_idt_handler_array as *const u8) };
    for (i, entry) in idt.iter_mut().enumerate() {
        *entry = IdtEntry::entry(handlers + (32 * i));
    }
}

unsafe fn init_ist_vectors(idt: &mut Idt) {
    let handler = VirtAddr::from(&stage2_idt_handler_array as *const u8) + (32 * DF_VECTOR);
    idt[DF_VECTOR] = IdtEntry::ist_entry(handler, IST_DF.try_into().unwrap());
}

pub fn early_idt_init() {
    unsafe {
        init_idt(&mut GLOBAL_IDT);
        load_idt(&GLOBAL_IDT);
    }
}

pub fn idt_init() {
    // Set IST vectors
    unsafe {
        init_ist_vectors(&mut GLOBAL_IDT);
    }
}

#[no_mangle]
fn stage2_generic_idt_handler(regs: &mut X86Regs) {
    if regs.vector == DF_VECTOR {
        let cr2 = read_cr2();
        let rip = regs.rip;
        let rsp = regs.rsp;
        panic!(
            "Double-Fault at RIP {:#018x} RSP: {:#018x} CR2: {:#018x}",
            rip, rsp, cr2
        );
    } else if regs.vector == VC_VECTOR {
        handle_vc_exception(regs);
    } else if regs.vector == BP_VECTOR {
        handle_bp_exception(regs);
    } else {
        let err = regs.error_code;
        let vec = regs.vector;
        let rip = regs.rip;

        panic!(
            "Unhandled exception {} RIP {:#018x} error code: {:#018x}",
            vec, rip, err
        );
    }
}

extern "C" {
    static stage2_idt_handler_array: u8;
}

fn handle_vc_exception(regs: &mut X86Regs) {
    let err = regs.error_code;
    let rip = regs.rip;

    // If the debugger is enabled then handle the DB exception
    // by directly invoking the exception handler
    if err == (SVM_EXIT_EXCP_BASE + X86_TRAP_DB) {
        handle_db_exception(regs);
        return;
    }

    panic!(
        "Unhandled #VC exception RIP {:#018x} error code: {:#018x}",
        rip, err
    );
}

// Entry Code
global_asm!(
    r#"
        .text
    push_regs:
        pushq   %rax
        pushq   %rbx
        pushq   %rcx
        pushq   %rdx
        pushq   %rsi
        pushq   %rdi
        pushq   %rbp
        pushq   %r8
        pushq   %r9
        pushq   %r10
        pushq   %r11
        pushq   %r12
        pushq   %r13
        pushq   %r14
        pushq   %r15

        movq    %rsp, %rdi
        call    stage2_generic_idt_handler

        .align 32
        .globl stage2_idt_handler_array
    stage2_idt_handler_array:
        i = 0
        .rept 32
        .align 32
        .if ((0x20027d00 >> i) & 1) == 0
        pushq   $0
        .endif
        pushq   $i  /* Vector Number */
        jmp push_regs
        i = i + 1
        .endr
        "#,
    options(att_syntax)
);
