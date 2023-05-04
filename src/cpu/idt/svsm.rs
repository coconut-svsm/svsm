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
    load_idt, Idt, IdtEntry, BP_VECTOR, DF_VECTOR, GLOBAL_IDT, GP_VECTOR, PF_VECTOR, VC_VECTOR,
};
use crate::address::VirtAddr;
use crate::cpu::X86ExceptionContext;
use crate::debug::gdbstub::svsm_gdbstub::handle_debug_exception;
use core::arch::global_asm;

fn init_idt(idt: &mut Idt) {
    // Set IDT handlers
    let handlers = unsafe { VirtAddr::from(&svsm_idt_handler_array as *const u8) };
    for (i, entry) in idt.iter_mut().enumerate() {
        *entry = IdtEntry::entry(handlers + (32 * i));
    }
}

unsafe fn init_ist_vectors(idt: &mut Idt) {
    let handler = VirtAddr::from(&svsm_idt_handler_array as *const u8) + (32 * DF_VECTOR);
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
pub fn generic_idt_handler(ctx: &mut X86ExceptionContext) {
    if ctx.vector == DF_VECTOR {
        let cr2 = read_cr2();
        let rip = ctx.frame.rip;
        let rsp = ctx.frame.rsp;
        panic!(
            "Double-Fault at RIP {:#018x} RSP: {:#018x} CR2: {:#018x}",
            rip, rsp, cr2
        );
    } else if ctx.vector == GP_VECTOR {
        let rip = ctx.frame.rip;
        let err = ctx.error_code;

        if !handle_exception_table(ctx) {
            panic!(
                "Unhandled General-Protection-Fault at RIP {:#018x} error code: {:#018x}",
                rip, err
            );
        }
    } else if ctx.vector == PF_VECTOR {
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
    } else if ctx.vector == VC_VECTOR {
        handle_vc_exception(ctx);
    } else if ctx.vector == BP_VECTOR {
        handle_debug_exception(ctx, ctx.vector);
    } else {
        let err = ctx.error_code;
        let vec = ctx.vector;
        let rip = ctx.frame.rip;

        if !handle_exception_table(ctx) {
            panic!(
                "Unhandled exception {} RIP {:#018x} error code: {:#018x}",
                vec, rip, err
            );
        }
    }
}

extern "C" {
    static svsm_idt_handler_array: u8;
}

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
        call    generic_idt_handler

        jmp generic_idt_handler_return
    
        .align 32
        .globl svsm_idt_handler_array
    svsm_idt_handler_array:
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
