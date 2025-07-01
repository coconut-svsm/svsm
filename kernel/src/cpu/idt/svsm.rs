// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::super::control_regs::read_cr2;
use super::super::extable::{handle_exception_table, handle_exception_table_early};
use super::super::ipi::handle_ipi_interrupt;
use super::super::percpu::{current_task, this_cpu};
use super::super::tss::IST_DF;
use super::super::vc::handle_vc_exception;
use super::super::x86::apic_eoi;
use super::common::{
    user_mode, IdtEntry, IdtEventType, PageFaultError, AC_VECTOR, BP_VECTOR, BR_VECTOR, CP_VECTOR,
    DB_VECTOR, DE_VECTOR, DF_VECTOR, GP_VECTOR, HV_VECTOR, IDT, INT_INJ_VECTOR, IPI_VECTOR,
    MCE_VECTOR, MF_VECTOR, NMI_VECTOR, NM_VECTOR, NP_VECTOR, OF_VECTOR, PF_VECTOR, SS_VECTOR,
    SX_VECTOR, TS_VECTOR, UD_VECTOR, VC_VECTOR, VE_VECTOR, XF_VECTOR,
};
use crate::address::VirtAddr;
use crate::cpu::irq_state::{raw_get_tpr, raw_set_tpr, tpr_from_vector};
use crate::cpu::registers::RFlags;
use crate::cpu::shadow_stack::IS_CET_SUPPORTED;
use crate::cpu::X86ExceptionContext;
use crate::debug::gdbstub::svsm_gdbstub::handle_debug_exception;
use crate::error::SvsmError;
use crate::mm::{GuestPtr, PageBox, PAGE_SIZE};
use crate::task::{is_task_fault, terminate};
use crate::tdx::ve::handle_virtualization_exception;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use core::arch::global_asm;
use core::mem;
use core::mem::offset_of;
use core::num::NonZero;

use crate::syscall::*;
use syscall::*;

pub static GLOBAL_IDT: ImmutAfterInitCell<IDT<'_>> = ImmutAfterInitCell::uninit();

pub fn load_static_idt() {
    // SAFETY: If the static reference is initialized, then it points to data
    // that can safely be used as an IDT with a static lifetime.  If it is
    // not initialized, then the borrow will panic.
    unsafe {
        GLOBAL_IDT.load();
    }
}

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
    fn asm_entry_pf_early();
    fn asm_entry_pf();
    fn asm_entry_mf();
    fn asm_entry_ac();
    fn asm_entry_mce();
    fn asm_entry_xf();
    fn asm_entry_ve();
    fn asm_entry_cp();
    fn asm_entry_hv();
    fn asm_entry_vc();
    fn asm_entry_sx();
    fn asm_entry_int80();
    fn asm_entry_irq_int_inj();
    fn asm_entry_irq_ipi();

    pub static mut HV_DOORBELL_ADDR: usize;
}

fn init_ist_vectors(idt: &mut IDT<'_>) {
    idt.set_entry(DF_VECTOR, IdtEntry::ist_entry(asm_entry_df, IST_DF.get()));
}

fn init_idt_exceptions(idt: &mut IDT<'_>) {
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
    idt.set_entry(PF_VECTOR, IdtEntry::entry(asm_entry_pf_early));
    idt.set_entry(MF_VECTOR, IdtEntry::entry(asm_entry_mf));
    idt.set_entry(AC_VECTOR, IdtEntry::entry(asm_entry_ac));
    idt.set_entry(MCE_VECTOR, IdtEntry::entry(asm_entry_mce));
    idt.set_entry(XF_VECTOR, IdtEntry::entry(asm_entry_xf));
    idt.set_entry(VE_VECTOR, IdtEntry::entry(asm_entry_ve));
    idt.set_entry(CP_VECTOR, IdtEntry::entry(asm_entry_cp));
    idt.set_entry(HV_VECTOR, IdtEntry::entry(asm_entry_hv));
    idt.set_entry(VC_VECTOR, IdtEntry::entry(asm_entry_vc));
    idt.set_entry(SX_VECTOR, IdtEntry::entry(asm_entry_sx));
}

/// # Safety
/// The caller must guarantee that the IDT object passed in does not go out of
/// scope before the IDT is reloaded with a different object.
pub unsafe fn early_idt_init(idt: &mut IDT<'_>) {
    // Initialize the exception portion of the IDT.
    init_idt_exceptions(idt);

    // Load IDT
    // SAFETY: the caller guarantees that the lifetime of the IDT object is
    // appropriate for use here.
    unsafe {
        idt.load();
    }
}

pub fn idt_init() -> Result<(), SvsmError> {
    // Allocate a page of memory to use as the IDT.
    let count = NonZero::new(PAGE_SIZE / mem::size_of::<IdtEntry>()).unwrap();
    let idt_page = PageBox::<[IdtEntry]>::try_new_slice(IdtEntry::no_handler(), count)?;
    let mut idt = IDT::new_from_page(idt_page);

    // Configure the exception vectors
    init_idt_exceptions(&mut idt);

    // Switch #PF handler to the default one
    idt.set_entry(PF_VECTOR, IdtEntry::entry(asm_entry_pf));

    // Interupts
    idt.set_entry(INT_INJ_VECTOR, IdtEntry::entry(asm_entry_irq_int_inj));
    idt.set_entry(0x80, IdtEntry::user_entry(asm_entry_int80));
    idt.set_entry(IPI_VECTOR, IdtEntry::entry(asm_entry_irq_ipi));

    // Set IST vectors
    init_ist_vectors(&mut idt);

    // SAFETY:
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

    // SAFETY: the IDT page was allocated above and is permanently associated
    // with the IDT, so it can safely be loaded now.
    unsafe {
        idt.load();
    }

    GLOBAL_IDT.init(idt).map_err(|_| SvsmError::PlatformInit)
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

// Early Page-Fault handler
#[no_mangle]
extern "C" fn ex_handler_page_fault_early(ctxt: &mut X86ExceptionContext, _vector: usize) {
    let cr2 = read_cr2();
    let rip = ctxt.frame.rip;
    let err = ctxt.error_code;

    if !handle_exception_table_early(ctxt) {
        panic!(
            "Unhandled early Page-Fault at RIP {:#018x} CR2: {:#018x} error code: {:#018x}",
            rip, cr2, err
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
            // SAFETY: `rsp` is a valid guest address filled by the CPU in the
            // X86InterruptFrame
            let ret = unsafe { ret_ptr.read() }.expect("Failed to read return address");

            // Read the return address on the shadow stack.
            let prev_rssp_ptr: GuestPtr<u64> = GuestPtr::new(VirtAddr::from(ctxt.ssp));
            // SAFETY: `ssp` is a valid guest address filled by the CPU in the
            // X86ExceptionContext
            let prev_rssp = unsafe { prev_rssp_ptr.read() }
                .expect("Failed to read address of previous shadow stack pointer");
            // The offset to the return pointer is different for RET and IRET.
            let offset = if code == NEAR_RET { 0 } else { 8 };
            let ret_ptr: GuestPtr<u64> = GuestPtr::new(VirtAddr::from(prev_rssp + offset));
            let ret_on_ssp =
                // SAFETY: `ssp` is a valid guest address filled by the CPU in the
                // X86ExceptionContext
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

// Virtualization Exception handler
#[no_mangle]
extern "C" fn ex_handler_ve(ctxt: &mut X86ExceptionContext) {
    let rip = ctxt.frame.rip;
    let code = ctxt.error_code;

    if let Err(err) = handle_virtualization_exception(ctxt) {
        log::error!("#VE handling error: {:?}", err);
        if user_mode(ctxt) {
            log::error!("Failed to handle #VE from user-mode at RIP {:#018x} code: {:#018x} - Terminating task", rip, code);
            terminate();
        } else {
            panic!(
                "Failed to handle #VE from kernel-mode at RIP {:#018x} code: {:#018x}",
                rip, code
            );
        }
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
        // Class 0 SysCalls.
        SYS_EXIT => sys_exit(ctxt.regs.rdi as u32),
        SYS_EXEC => sys_exec(ctxt.regs.rdi, ctxt.regs.rsi, ctxt.regs.r8),
        SYS_CLOSE => sys_close(ctxt.regs.rdi as u32),
        // Class 1 SysCalls.
        SYS_OPEN => sys_open(ctxt.regs.rdi, ctxt.regs.rsi, ctxt.regs.r8),
        SYS_READ => sys_read(ctxt.regs.rdi as u32, ctxt.regs.rsi, ctxt.regs.r8),
        SYS_WRITE => sys_write(ctxt.regs.rdi as u32, ctxt.regs.rsi, ctxt.regs.r8),
        SYS_SEEK => sys_seek(ctxt.regs.rdi as u32, ctxt.regs.rsi, ctxt.regs.r8),
        SYS_UNLINK => sys_unlink(ctxt.regs.rdi),
        SYS_TRUNCATE => sys_truncate(ctxt.regs.rdi as u32, ctxt.regs.rsi),
        SYS_OPENDIR => sys_opendir(ctxt.regs.rdi),
        SYS_READDIR => sys_readdir(ctxt.regs.rdi as u32, ctxt.regs.rsi, ctxt.regs.r8),
        SYS_MKDIR => sys_mkdir(ctxt.regs.rdi),
        SYS_RMDIR => sys_rmdir(ctxt.regs.rdi),
        // Class 3 SysCalls.
        SYS_CAPABILITIES => sys_capabilities(ctxt.regs.rdi as u32),
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

pub fn common_isr_handler(vector: usize) {
    // Set TPR based on the vector being handled and reenable interrupts to
    // permit delivery of higher priority interrupts.  Because this routine
    // dispatches interrupts which should only be observable if interrupts
    // are enabled, the IRQ nesting count must be zero at this point.
    let previous_tpr = raw_get_tpr();
    raw_set_tpr(tpr_from_vector(vector));

    let cpu = this_cpu();
    cpu.irqs_enable();

    // Process the requested interrupt vector.
    match vector {
        IPI_VECTOR => handle_ipi_interrupt(),
        _ => {
            // Ignore all unrecognized interrupt vectors and treat them as
            // spurious interrupts.
        }
    }

    // Disable interrupts before restoring TPR.
    cpu.irqs_disable();
    raw_set_tpr(previous_tpr);

    // Perform the EOI cycle after the interrupt processing state has been
    // restored so that recurrent interrupts will not introduce recursion at
    // this point.
    apic_eoi();
}

global_asm!(
    r#"
        .set const_false, 0
        .set const_true, 1
    "#,
    concat!(".set CFG_NOSMAP, const_", cfg!(feature = "nosmap")),
    include_str!("../x86/smap.S"),
    include_str!("svsm_entry.S"),
    IF = const RFlags::IF.bits(),
    EXCEP_R15_OFF = const offset_of!(X86ExceptionContext, regs.r15),
    EXCEP_R14_OFF = const offset_of!(X86ExceptionContext, regs.r14),
    EXCEP_R13_OFF = const offset_of!(X86ExceptionContext, regs.r13),
    EXCEP_R12_OFF = const offset_of!(X86ExceptionContext, regs.r12),
    EXCEP_R11_OFF = const offset_of!(X86ExceptionContext, regs.r11),
    EXCEP_R10_OFF = const offset_of!(X86ExceptionContext, regs.r10),
    EXCEP_R9_OFF = const offset_of!(X86ExceptionContext, regs.r9),
    EXCEP_R8_OFF = const offset_of!(X86ExceptionContext, regs.r8),
    EXCEP_RBP_OFF = const offset_of!(X86ExceptionContext, regs.rbp),
    EXCEP_RDI_OFF = const offset_of!(X86ExceptionContext, regs.rdi),
    EXCEP_RSI_OFF = const offset_of!(X86ExceptionContext, regs.rsi),
    EXCEP_RDX_OFF = const offset_of!(X86ExceptionContext, regs.rdx),
    EXCEP_RCX_OFF = const offset_of!(X86ExceptionContext, regs.rcx),
    EXCEP_RBX_OFF = const offset_of!(X86ExceptionContext, regs.rbx),
    EXCEP_RAX_OFF = const offset_of!(X86ExceptionContext, regs.rax),
    EXCEP_RIP_OFF = const offset_of!(X86ExceptionContext, frame.rip),
    EXCEP_RSP_OFF = const offset_of!(X86ExceptionContext, frame.rsp),
    EXCEP_CS_OFF = const offset_of!(X86ExceptionContext, frame.cs),
    EXCEP_FLAGS_OFF = const offset_of!(X86ExceptionContext, frame.flags),
    EXCEP_FRAME_OFF = const offset_of!(X86ExceptionContext, frame),
    IS_CET_SUPPORTED = sym IS_CET_SUPPORTED,
    options(att_syntax)
);
