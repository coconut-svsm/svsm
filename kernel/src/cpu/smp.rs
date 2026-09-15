// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::acpi::tables::ACPICPUInfo;
use crate::address::Address;
use crate::address::PhysAddr;
use crate::cpu::cpulaunch::{CpuLaunch, initialize_cpu};
use crate::cpu::idt::load_static_idt;
use crate::cpu::percpu::{PERCPU_AREAS, PerCpu, PerCpuShared, this_cpu};
use crate::cpu::shadow_stack::{
    MODE_64BIT, S_CET, SCetFlags, initial_shadow_stack, is_cet_ss_enabled,
};
use crate::cpu::sse::sse_init;
use crate::cpu::tlb::set_tlb_flush_smp;
use crate::enable_shadow_stacks;
use crate::error::SvsmError;
use crate::hyperv;
use crate::mm::{PerCPUPageMappingGuard, phys_to_virt};
use crate::platform::{SVSM_PLATFORM, SvsmPlatform};
use crate::task::schedule_init;
use alloc::boxed::Box;
use bootdefs::kernel_launch::ApStartContext;
use core::arch::global_asm;
use core::mem::size_of;
use core::sync::atomic::{Ordering, fence};
use cpuarch::x86::EFERFlags;

percpu! {
    #[percpu_asm_symbol("__svsm_percpu_shared")]
    static PERCPU_SHARED: &'static PerCpuShared;
}

pub(super) fn init_percpu_shared(percpu_shared: &'static PerCpuShared) {
    assert!(PERCPU_SHARED.init(percpu_shared).is_ok());
}

pub fn this_cpu_shared() -> &'static PerCpuShared {
    PERCPU_SHARED.with(|percpu_shared| *percpu_shared)
}

#[derive(Debug)]
pub struct ApStartContextRef {
    mapping: PerCPUPageMappingGuard,
}

impl ApStartContextRef {
    /// # Safety
    /// The caller is required to specify a correct address for the AP start
    /// context.
    pub unsafe fn new(ap_start_context_addr: u32) -> Result<Self, SvsmError> {
        let paddr = PhysAddr::from(u64::from(ap_start_context_addr));
        let mapping = PerCPUPageMappingGuard::create_4k(paddr)?;
        Ok(Self { mapping })
    }

    pub fn as_mut_ptr(&self) -> *mut ApStartContext {
        self.mapping.virt_addr().as_mut_ptr::<ApStartContext>()
    }
}

/// # Safety
fn start_cpu(
    platform: &dyn SvsmPlatform,
    percpu_shared: &'static PerCpuShared,
    ap_start_context_ref: Option<&ApStartContextRef>,
) -> Result<(), SvsmError> {
    let start_rip: u64 = start_ap_entry as *const () as usize as u64;
    let percpu = PerCpu::alloc(percpu_shared)?;
    let pgtable = this_cpu().new_pgtable()?;
    percpu.setup(pgtable)?;

    let stack_slot = percpu
        .get_top_of_context_switch_stack()
        .unwrap()
        .checked_sub(size_of::<*mut CpuLaunch>())
        .unwrap();
    let stack_slot_paddr = percpu.get_pgtable().phys_addr(stack_slot)?;
    let stack_slot_vaddr = phys_to_virt(stack_slot_paddr);
    let launch = Box::new(CpuLaunch::new_application(percpu));
    let launch_ptr = Box::into_raw(launch);

    // SAFETY: the stack slot is backed by the target CPU's private stack and
    // is not visible to that CPU until the launch operation below. The AP
    // entry shim consumes this pointer before using the stack.
    unsafe {
        stack_slot_vaddr
            .as_mut_ptr::<*mut CpuLaunch>()
            .write(launch_ptr);
    }
    fence(Ordering::Release);

    if let Err(err) = platform.start_cpu(percpu, start_rip, ap_start_context_ref) {
        // SAFETY: a failed platform launch did not release the target CPU, so
        // ownership of the launch record remains with this CPU.
        drop(unsafe { Box::from_raw(launch_ptr) });
        return Err(err);
    }

    let percpu_shared = percpu.shared();
    while !percpu_shared.is_online() {}
    Ok(())
}

pub fn start_secondary_cpus(
    platform: &dyn SvsmPlatform,
    cpus: &[ACPICPUInfo],
    ap_start_context_ref: Option<&ApStartContextRef>,
) {
    // Create the shared CPU structures for each application processor
    // while still running single processor.  This ensures that the
    // PERCPU_AREAS array is completely initialized before any additional
    // processor starts running.
    for c in cpus.iter().filter(|c| c.apic_id != 0 && c.enabled) {
        // SAFETY: it is safe to create new shraed CPU areas because the system
        // is still running single processor.
        unsafe {
            PERCPU_AREAS.create_new(c.apic_id);
        }
    }

    // Now loop over all CPUs to start them.
    for (cpu_index, percpu_shared) in PERCPU_AREAS.iter().enumerate() {
        // CPU 0 is already running, so it doesn't require processing.
        if cpu_index != 0 {
            // If this is the first AP being started, then advise the TLB
            // package that future TLB flushes will have to be done with SMP
            // scope.
            if cpu_index == 1 {
                set_tlb_flush_smp();
            }

            log::info!(
                "Launching AP {} with APIC-ID {}",
                cpu_index,
                percpu_shared.apic_id()
            );
            start_cpu(platform, percpu_shared, ap_start_context_ref).expect("failed");
        }
    }
}

unsafe extern "C" {
    fn start_ap_indirect();
    fn start_ap_entry();
}

global_asm!(
    r#"
        .section .text
        .globl start_ap_indirect
    start_ap_indirect:
        /*
         * %rdi stores the address of ApStartContext
         * Load fields from the context structure
         */
        movq    (%rdi), %r8     /* CR0 */
        movq    8(%rdi), %r9    /* CR3 */
        movq    16(%rdi), %r10  /* CR4 */
        movl    24(%rdi), %eax  /* Low bits of EFER */
        movl    28(%rdi), %edx  /* High bits of EFER */
        movq    32(%rdi), %r12  /* Start RIP */
        movq    40(%rdi), %rsp  /* Initial RSP */

        /* Switch to the target environment.  This will remove the transition
         * environment and context structure from the address space. */
        movq    %r8, %cr0
        movq    %r10, %cr4

        /* Check to see whether EFER.LME is specified.  If not, then EFER
         * should not be reloaded. */
        testl   ${LME}, %eax
        je      1f
        movl    $0xC0000080, %ecx   /* EFER */
        wrmsr
    1:
        movq    %r9, %cr3

        /* Mark the next stack frame as the bottom frame */
        xor     %rbp, %rbp

        /* Begin execution from the starting RIP */
        jmp     *%r12
        int3

        .globl start_ap_entry
    start_ap_entry:
        /* Consume the owned CpuLaunch pointer from the initial stack. */
        popq    %rdi
        call    start_ap
        int3
        "#,
    LME = const EFERFlags::LME.bits(),
    options(att_syntax)
);

pub fn set_ap_start_context(
    initial_context: &hyperv::HvInitialVpContext,
    ap_start_context_ref: &ApStartContextRef,
) {
    // SAFETY: the safety of the AP start context ref was guaranteed when the
    // object was created.
    unsafe {
        ap_start_context_ref.as_mut_ptr().write(ApStartContext {
            cr0: initial_context.cr0.try_into().unwrap(),
            cr3: initial_context.cr3.try_into().unwrap(),
            cr4: initial_context.cr4.try_into().unwrap(),
            efer: initial_context.efer.try_into().unwrap(),
            start_rip: initial_context.rip.try_into().unwrap(),
            rsp: initial_context.rsp.try_into().unwrap(),
            initial_rip: start_ap_indirect as *const () as usize,
        });
    }
}

#[unsafe(no_mangle)]
extern "C" fn start_ap(launch: *mut CpuLaunch) -> ! {
    fence(Ordering::Acquire);
    // SAFETY: the BSP created this pointer with Box::into_raw() and transfers
    // ownership exactly once through the initial AP stack slot.
    let launch = unsafe { Box::from_raw(launch) };
    let percpu = launch.percpu();

    initialize_cpu(*launch, &**SVSM_PLATFORM).expect("Failed to initialize AP");
    load_static_idt();

    if is_cet_ss_enabled() {
        let ssp_token = initial_shadow_stack().unwrap();
        enable_shadow_stacks!(ssp_token);
    }

    percpu
        .setup_idle_task()
        .expect("Failed to allocate idle task for AP");

    // Send a life-sign
    log::info!("CPU {} is online", this_cpu().get_cpu_index());

    // Set CPU online so that BSP can proceed
    this_cpu_shared().set_online();

    sse_init();

    // SAFETY: there is no current task running on this processor yet, so
    // initializing the scheduler is safe.
    unsafe {
        schedule_init();
    }

    unreachable!("Road ends here!");
}
