// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::acpi::tables::ACPICPUInfo;
use crate::address::{Address, VirtAddr};
use crate::cpu::efer::EFERFlags;
use crate::cpu::idt::idt;
use crate::cpu::ipi::ipi_start_cpu;
use crate::cpu::percpu::{
    cpu_idle_loop, this_cpu, this_cpu_shared, PerCpu, PerCpuShared, PERCPU_AREAS,
};
use crate::cpu::shadow_stack::{is_cet_ss_supported, SCetFlags, MODE_64BIT, S_CET};
use crate::cpu::sse::sse_init;
use crate::cpu::tlb::set_tlb_flush_smp;
use crate::enable_shadow_stacks;
use crate::error::SvsmError;
use crate::hyperv;
use crate::mm::STACK_SIZE;
use crate::platform::{SvsmPlatform, SVSM_PLATFORM};
use crate::task::schedule_init;
use crate::utils::MemoryRegion;

use bootlib::kernel_launch::ApStartContext;
use core::arch::global_asm;
use core::mem;

fn start_cpu(
    platform: &dyn SvsmPlatform,
    percpu_shared: &'static PerCpuShared,
) -> Result<(), SvsmError> {
    let start_rip: u64 = (start_ap as *const u8) as u64;
    let percpu = PerCpu::alloc(percpu_shared)?;
    let pgtable = this_cpu().get_pgtable().clone_shared()?;
    percpu.setup(platform, pgtable)?;

    platform.start_cpu(percpu, start_rip)?;

    let percpu_shared = percpu.shared();
    while !percpu_shared.is_online() {}
    Ok(())
}

pub fn start_secondary_cpus(platform: &dyn SvsmPlatform, cpus: &[ACPICPUInfo]) {
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
            start_cpu(platform, percpu_shared).expect("failed");
        }
    }
}

#[no_mangle]
extern "C" fn start_ap_setup(top_of_stack: u64) {
    // Initialize the GDT, TSS, and IDT.
    this_cpu().load_gdt_tss(true);
    idt().load();
    // Now the stack unwinder can be used
    this_cpu().set_current_stack(MemoryRegion::new(
        VirtAddr::from(top_of_stack)
            .checked_sub(STACK_SIZE)
            .unwrap(),
        STACK_SIZE,
    ));
}

extern "C" {
    fn start_ap_indirect();
}

global_asm!(
    r#"
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

        /* Make sure stack frames are 16b-aligned */
        andq    $~0xf, %rsp

        /* Mark the next stack frame as the bottom frame */
        xor     %rbp, %rbp

        /*
         * Call a startup function to complete setup in the local
         * environment.
         *
         * %r12 is preserved per x86-64 calling convention.
         */
        mov     %rsp, %rdi
        call    start_ap_setup

        /* Begin execution from the starting RIP */
        call    *%r12
        int3
        "#,
    LME = const EFERFlags::LME.bits(),
    options(att_syntax)
);

pub fn create_ap_start_context(
    initial_context: &hyperv::HvInitialVpContext,
    transition_cr3: u32,
) -> ApStartContext {
    ApStartContext {
        cr0: initial_context.cr0.try_into().unwrap(),
        cr3: initial_context.cr3.try_into().unwrap(),
        cr4: initial_context.cr4.try_into().unwrap(),
        efer: initial_context.efer.try_into().unwrap(),
        start_rip: initial_context.rip.try_into().unwrap(),
        rsp: initial_context.rsp.try_into().unwrap(),
        transition_cr3,
        initial_rip: start_ap_indirect as usize,
        context_size: mem::size_of::<ApStartContext>() as u32,
    }
}

#[no_mangle]
extern "C" fn start_ap() -> ! {
    let percpu = this_cpu();

    if is_cet_ss_supported() {
        enable_shadow_stacks!(percpu);
    }

    percpu
        .setup_on_cpu(&**SVSM_PLATFORM)
        .expect("setup_on_cpu() failed");

    percpu
        .setup_idle_task(cpu_idle_loop)
        .expect("Failed to allocate idle task for AP");

    // Send a life-sign
    log::info!("CPU {} is online", this_cpu().get_cpu_index());

    // Mark this CPU as participating in IPI usage.
    ipi_start_cpu();

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
