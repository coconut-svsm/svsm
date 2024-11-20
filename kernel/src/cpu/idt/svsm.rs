// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Authors: Joerg Roedel <jroedel@suse.de>

use super::super::control_regs::read_cr2;
use super::super::extable::handle_exception_table;
use super::super::percpu::{current_task, this_cpu};
use super::super::tss::IST_DF;
use super::super::vc::handle_vc_exception;
use super::common::{
    idt_mut, user_mode, IdtEntry, IdtEventType, PageFaultError, AC_VECTOR, BP_VECTOR, BR_VECTOR,
    CP_VECTOR, DB_VECTOR, DE_VECTOR, DF_VECTOR, GP_VECTOR, HV_VECTOR, INT_INJ_VECTOR, MCE_VECTOR,
    MF_VECTOR, NMI_VECTOR, NM_VECTOR, NP_VECTOR, OF_VECTOR, PF_VECTOR, SS_VECTOR, SX_VECTOR,
    TS_VECTOR, UD_VECTOR, VC_VECTOR, XF_VECTOR,
};
use crate::address::VirtAddr;
use crate::cpu::registers::RFlags;
use crate::cpu::shadow_stack::IS_CET_SUPPORTED;
use crate::cpu::X86ExceptionContext;
use crate::debug::gdbstub::svsm_gdbstub::handle_debug_exception;
use crate::mm::GuestPtr;
use crate::platform::SVSM_PLATFORM;
use crate::task::{is_task_fault, terminate};
use core::arch::global_asm;

use crate::syscall::*;
use syscall::*;

extern "C" {
    pub fn return_new_task();
    pub fn default_return();
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
    fn asm_entry_int80();
    fn asm_entry_irq_int_inj();

    pub static mut HV_DOORBELL_ADDR: usize;
}

fn init_ist_vectors() {
    idt_mut().set_entry(DF_VECTOR, IdtEntry::ist_entry(asm_entry_df, IST_DF.get()));
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
    idt.set_entry(INT_INJ_VECTOR, IdtEntry::entry(asm_entry_irq_int_inj));

    // Interupts
    idt.set_entry(0x80, IdtEntry::user_entry(asm_entry_int80));

    // Load IDT
    idt.load();
}

pub fn idt_init() {
    // Set IST vectors
    init_ist_vectors();

    // Capture an address that can be used by assembly code to read the #HV
    // doorbell page.  The address of each CPU's doorbell page may be
    // different, but the address of the field in the PerCpu structure that
    // holds the actual pointer is constant across all CPUs, so that is the
    // pointer that is actually captured.  The address that is captured is
    // stored as a usize instead of a typed value, because the declarations
    // required for type safety here are cumbersome, and the assembly code
    // that uses the value is not type safe in any case, so enforcing type
    // safety on the pointer would offer no meaningful value.
    unsafe {
        HV_DOORBELL_ADDR = this_cpu().hv_doorbell_addr() as usize;
    };
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
extern "C" fn ex_handler_double_fault(ctxt: &mut X86ExceptionContext) {
    let cr2 = read_cr2();
    let rip = ctxt.frame.rip;
    let rsp = ctxt.frame.rsp;

    if user_mode(ctxt) {
        log::error!(
            "Double-Fault at RIP {:#018x} RSP: {:#018x} CR2: {:#018x} - Terminating task",
            rip,
            rsp,
            cr2
        );
        terminate();
    } else {
        panic!(
            "Double-Fault at RIP {:#018x} RSP: {:#018x} CR2: {:#018x}",
            rip, rsp, cr2
        );
    }
}

// General-Protection handler
#[no_mangle]
extern "C" fn ex_handler_general_protection(ctxt: &mut X86ExceptionContext) {
    let rip = ctxt.frame.rip;
    let err = ctxt.error_code;
    let rsp = ctxt.frame.rsp;

    if user_mode(ctxt) {
        log::error!(
            "Unhandled General-Protection-Fault at RIP {:#018x} error code: {:#018x} rsp: {:#018x} - Terminating task",
            rip, err, rsp);
        terminate();
    } else if !handle_exception_table(ctxt) {
        panic!(
            "Unhandled General-Protection-Fault at RIP {:#018x} error code: {:#018x} rsp: {:#018x}",
            rip, err, rsp
        );
    }
}

// Page-Fault handler
#[no_mangle]
extern "C" fn ex_handler_page_fault(ctxt: &mut X86ExceptionContext, vector: usize) {
    let cr2 = read_cr2();
    let rip = ctxt.frame.rip;
    let err = ctxt.error_code;
    let vaddr = VirtAddr::from(cr2);

    if user_mode(ctxt) {
        let kill_task: bool = if is_task_fault(vaddr) {
            current_task()
                .fault(vaddr, (err & PageFaultError::W.bits() as usize) != 0)
                .is_err()
        } else {
            true
        };

        if kill_task {
            log::error!("Unexpected user-mode page-fault at RIP {:#018x} CR2: {:#018x} error code: {:#018x} - Terminating task",
                    rip, cr2, err);
            terminate();
        }
    } else if this_cpu()
        .handle_pf(
            VirtAddr::from(cr2),
            (err & PageFaultError::W.bits() as usize) != 0,
        )
        .is_err()
        && !handle_exception_table(ctxt)
    {
        handle_debug_exception(ctxt, vector);
        panic!(
            "Unhandled Page-Fault at RIP {:#018x} CR2: {:#018x} error code: {:#018x}",
            rip, cr2, err
        );
    }
}

// Control-Protection handler
#[no_mangle]
extern "C" fn ex_handler_control_protection(ctxt: &mut X86ExceptionContext, _vector: usize) {
    // From AMD64 Architecture Programmer's Manual, Volume 2, 8.4.3
    // Control-Protection Error Code:
    /// A RET (near) instruction encountered a return address mismatch.
    const NEAR_RET: usize = 1;
    /// A RET (far) or IRET instruction encountered a return address mismatch.
    const FAR_RET_IRET: usize = 2;
    /// An RSTORSSP instruction encountered an invalid shadow stack restore
    /// token.
    const RSTORSSP: usize = 4;
    /// A SETSSBSY instruction encountered an invalid supervisor shadow stack
    /// token.
    const SETSSBSY: usize = 5;

    let rip = ctxt.frame.rip;
    match ctxt.error_code & 0x7fff {
        code @ (NEAR_RET | FAR_RET_IRET) => {
            // Read the return address on the normal stack.
            let ret_ptr: GuestPtr<u64> = GuestPtr::new(VirtAddr::from(ctxt.frame.rsp));
            let ret = unsafe { ret_ptr.read() }.expect("Failed to read return address");

            // Read the return address on the shadow stack.
            let prev_rssp_ptr: GuestPtr<u64> = GuestPtr::new(VirtAddr::from(ctxt.ssp));
            let prev_rssp = unsafe { prev_rssp_ptr.read() }
                .expect("Failed to read address of previous shadow stack pointer");
            // The offset to the return pointer is different for RET and IRET.
            let offset = if code == NEAR_RET { 0 } else { 8 };
            let ret_ptr: GuestPtr<u64> = GuestPtr::new(VirtAddr::from(prev_rssp + offset));
            let ret_on_ssp =
                unsafe { ret_ptr.read() }.expect("Failed to read return address on shadow stack");

            panic!("thread at {rip:#018x} tried to return to {ret:#x}, but return address on shadow stack was {ret_on_ssp:#x}!");
        }
        RSTORSSP => {
            panic!("rstorssp instruction encountered an unexpected shadow stack restore token at RIP {rip:#018x}");
        }
        SETSSBSY => {
            panic!("setssbsy instruction encountered an unexpected supervisor shadow stack token at RIP {rip:#018x}");
        }
        code => unreachable!("unexpected code for #CP exception: {code}"),
    }
}

// VMM Communication handler
#[no_mangle]
extern "C" fn ex_handler_vmm_communication(ctxt: &mut X86ExceptionContext, vector: usize) {
    let rip = ctxt.frame.rip;
    let code = ctxt.error_code;

    if let Err(err) = handle_vc_exception(ctxt, vector) {
        log::error!("#VC handling error: {:?}", err);
        if user_mode(ctxt) {
            log::error!("Failed to handle #VC from user-mode at RIP {:#018x} code: {:#018x} - Terminating task", rip, code);
            terminate();
        } else {
            panic!(
                "Failed to handle #VC from kernel-mode at RIP {:#018x} code: {:#018x}",
                rip, code
            );
        }
    }
}

// System Call SoftIRQ handler
#[no_mangle]
extern "C" fn ex_handler_system_call(
    ctxt: &mut X86ExceptionContext,
    vector: usize,
    event_type: IdtEventType,
) {
    // Ensure that this vector was not invoked as a hardware interrupt vector.
    if event_type.is_external_interrupt(vector) {
        panic!("Syscall handler invoked as external interrupt!");
    }

    if !user_mode(ctxt) {
        panic!("Syscall handler called from kernel mode!");
    }

    let Ok(input) = TryInto::<u64>::try_into(ctxt.regs.rax) else {
        ctxt.regs.rax = !0;
        return;
    };

    ctxt.regs.rax = match input {
        SYS_EXIT => sys_exit(ctxt.regs.rdi as u32),
        SYS_CLOSE => sys_close(ctxt.regs.rdi as u32),
        SYS_OPENDIR => sys_opendir(ctxt.regs.rdi),
        SYS_READDIR => sys_readdir(ctxt.regs.rdi as u32, ctxt.regs.rsi, ctxt.regs.r8),
        _ => Err(SysCallError::EINVAL),
    }
    .map_or_else(|e| e as usize, |v| v as usize);
}

#[no_mangle]
pub extern "C" fn ex_handler_panic(ctx: &mut X86ExceptionContext, vector: usize) {
    let rip = ctx.frame.rip;
    let err = ctx.error_code;
    let rsp = ctx.frame.rsp;
    let ss = ctx.frame.ss;
    panic!(
        "Unhandled exception {} RIP {:#018x} error code: {:#018x} RSP: {:#018x} SS: {:#x}",
        vector, rip, err, rsp, ss
    );
}

#[no_mangle]
pub extern "C" fn common_isr_handler_entry(vector: usize) {
    // Since interrupt handlers execute with interrupts disabled, it is
    // necessary to increment the per-CPU interrupt disable nesting state
    // while the handler is running in case common code attempts to disable
    // interrupts temporarily.  The fact that this interrupt was received
    // means that the previous state must have had interrupts enabled.
    let cpu = this_cpu();
    cpu.irqs_push_nesting(true);

    common_isr_handler(vector);

    // Decrement the interrupt disable nesting count, but do not permit
    // interrupts to be reenabled.  They will be reenabled during the IRET
    // flow.
    cpu.irqs_pop_nesting();
}

pub fn common_isr_handler(_vector: usize) {
    // Interrupt injection requests currently require no processing; they occur
    // simply to ensure an exit from the guest.

    // Treat any unhandled interrupt as a spurious interrupt.
    SVSM_PLATFORM.eoi();
}

global_asm!(
    r#"
        .set const_false, 0
        .set const_true, 1
    "#,
    concat!(".set CFG_NOSMAP, const_", cfg!(feature = "nosmap")),
    concat!(
        ".set CFG_SHADOW_STACKS, const_",
        cfg!(feature = "shadow-stacks")
    ),
    include_str!("../x86/smap.S"),
    include_str!("entry.S"),
    IF = const RFlags::IF.bits(),
    IS_CET_SUPPORTED = sym IS_CET_SUPPORTED,
    options(att_syntax)
);
