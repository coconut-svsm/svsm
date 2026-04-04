// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

#![no_std]
#![no_main]

use bootdefs::kernel_launch::BldrLaunchInfo;
use bootdefs::kernel_launch::KernelLaunchInfo;
use bootdefs::platform::SvsmPlatformType;
use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::arch::global_asm;
use core::mem::offset_of;
use core::slice;
use cpuarch::sev_status::MSR_SEV_STATUS;
use cpuarch::sev_status::SEVStatusFlags;
use cpuarch::x86::EFERFlags;
use cpuarch::x86::MSR_EFER;

global_asm!(
    r#"
        .text
        .section .startup.text,"ax"
        .code32

        .globl startup_32
        startup_32:

        /* Upon entry, ESI holds the high 32 bits of VTOM. */

        /* Save pointer to startup structure in EBP */
        movl %esp, %ebp

        /* Save the platform type for future use.  The platform type is loaded
         * in EAX upon entry. */
        movl %eax, {PLATFORM}(%ebp)

        /* Check to see whether this is an SNP system.  If not, no page table
         * manipulation is required. */
        cmpl $1, %eax
        jnz page_tables_ready

        /* Check to see whether vTOM is active on this system.  If so, no page
         * table manipulation is necessary */
        movl ${MSR_SEV_STATUS}, %ecx
        rdmsr
        testl ${VTOM}, %eax
        jnz page_tables_ready

        /* Locate the CPUID page */
        movl {CPUID_PAGE}(%ebp), %edx

        /* Determine the number of entries and the address of the first
         * entry.  The contents of the CPUID page have been validated by
         * the SNP firmware so the data can be trusted directly. */
        movl (%edx), %ecx
        leal 16(%edx), %edx

    10:
        /* Check to see whether this entry is the extended SEV leaf.  If not,
         * keep searching */
        cmpl $0x8000001F, (%edx)
        jz 11f
        leal 48(%edx), %edx
        dec %ecx
        jnz 10b
        ud2

    11:
        /* The C-bit position is encoded as the low 6 bits of the EBX field. */
        mov 28(%edx), %eax
        andl $0x3F, %eax

        /* Save the C-bit position for later use. */
        movl %eax, {C_BIT_POS}(%ebp)

        /* Obtain the bounds of the page tables */
        movl {PT_START}(%ebp), %ecx
        movl {PT_END}(%ebp), %edx

        /* Insert the C-bit into each valid PTE */
    1:
        testl $1, (%ecx)
        jz 2f
        bts %eax, (%ecx)
    2:
        addl $8, %ecx
        cmp %edx, %ecx
        jb 1b

    page_tables_ready:
        /* The page tables are now configured, so enable long mode. */
        movl ${MSR_EFER}, %ecx
        rdmsr

        /* Don't write the MSR if EFER_LME is already set.  This is required
         * for certain versions of the TDX module. */
        testl ${EFER_LME}, %eax
        jnz 3f

        /* Include NXE as well. */
        orl $({EFER_LME} | {EFER_NXE}), %eax
        wrmsr
    3:
        /* Enable paging so that long mode can be activated. */
        movl {PT_ROOT}(%ebp), %edx
        movl %edx, %cr3
        movl %cr0, %eax
        bts $31, %eax
        movl %eax, %cr0

        /* Establish the correct GDT and jump to the 64-bit entry point. */
        movl $gdt64_desc, %eax
        lgdt (%eax)
        ljmpl $0x8, $startup_64

        .code64

    startup_64:
        /* Reload the data segments with 64bit descriptors. */
        movw $0x10, %ax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %fs
        movw %ax, %gs
        movw %ax, %ss

        /*
         * Follow the C calling convention for x86-64:
         *
         * - Pass &BldrLaunchInfo as the first argument (%rdi)
         * - Pass VTOM as the second argument (%rsi)
         * - Make sure (%rsp + 8) is 16b-aligned when control is transferred
         *   to stage2_main
         */
        movl %ebp, %edi
        shlq $32, %rsi
        andq $~0xf, %rsp

        /* Mark the next stack frame as the bottom frame */
        xor %rbp, %rbp

        call bldr_main

        .globl switch_to_kernel
    switch_to_kernel:
        /* Switch to the kernel stack. */
        movq %rsi, %rsp

        /* Load the platform type into rax as expected by the kernel */
        movq %rdx, %rax

        /* Enter the kernel. */
        push %rdi
        ret

        .globl pvalidate_one
    pvalidate_one:
        movq %rdi, %rax
        xorl %ecx, %ecx
        movl $1, %edx
        pvalidate
        jb 1f
        ret
    1:
        ud2

        .data
        .align 16
    gdt64:
        .quad 0
        .quad 0x00af9a000000ffff /* 64 bit code segment */
        .quad 0x00cf92000000ffff /* 64 bit data segment */
    gdt64_end:

    gdt64_desc:
        .word gdt64_end - gdt64 - 1
        .quad gdt64

        "#,
    MSR_EFER = const MSR_EFER,
    EFER_NXE = const EFERFlags::NXE.bits(),
    EFER_LME = const EFERFlags::LME.bits(),
    MSR_SEV_STATUS = const MSR_SEV_STATUS,
    VTOM = const SEVStatusFlags::VTOM.bits(),
    PT_START = const offset_of!(BldrLaunchInfo, page_table_start) as u32,
    PT_END = const offset_of!(BldrLaunchInfo, page_table_end) as u32,
    PT_ROOT = const offset_of!(BldrLaunchInfo, page_table_root) as u32,
    CPUID_PAGE = const offset_of!(BldrLaunchInfo, cpuid_addr) as u32,
    PLATFORM = const offset_of!(BldrLaunchInfo, platform_type) as u32,
    C_BIT_POS = const offset_of!(BldrLaunchInfo, c_bit_position) as u32,
    options(att_syntax)
);

unsafe extern "C" {
    fn switch_to_kernel(entry: u64, initial_stack: u64, platform_type: u64) -> !;
    fn pvalidate_one(addr: u64);
}

fn copy_cpuid_page(launch_info: &BldrLaunchInfo, kernel_launch_info: &mut KernelLaunchInfo) {
    // SAFETY: the addresses described in the launch info pages are correct
    // for use for copying.
    unsafe {
        // The kernel CPUID page must be validated before it can be filled
        // since it behaves like a loader-populated page.
        pvalidate_one(kernel_launch_info.cpuid_page);
        let src = slice::from_raw_parts(launch_info.cpuid_addr as usize as *const u8, 0x1000);
        let dst = slice::from_raw_parts_mut(kernel_launch_info.cpuid_page as *mut u8, 0x1000);
        dst.copy_from_slice(src);
    }
}

fn update_kernel_page_tables(launch_info: &BldrLaunchInfo, confidentiality_mask: u64) {
    // SAFETY: the launch info correctly describes the bounds of the kernel
    // page tables.
    let page_tables = unsafe {
        slice::from_raw_parts_mut(
            launch_info.kernel_pt_vaddr as *mut u64,
            launch_info.kernel_pt_count as usize * 0x200,
        )
    };

    // Update all valid PTEs with the confidentiality mask.
    for pte in page_tables {
        if (*pte & 1) != 0 {
            *pte |= confidentiality_mask;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bldr_main(launch_info: &BldrLaunchInfo, vtom: u64) -> ! {
    // Map the kernel virtual address range into the current page tables.
    // SAFETY: the launch information correctly describes the current page
    // tables so their contents can be obtained as a slice.
    let page_tables =
        unsafe { slice::from_raw_parts_mut(launch_info.page_table_root as usize as *mut u64, 512) };

    // Determine the correct confidentiality mask for this platform.
    let platform_type = SvsmPlatformType::from(launch_info.platform_type);
    let confidentiality_mask =
        if (platform_type == SvsmPlatformType::Snp) && (launch_info.c_bit_position != 0) {
            1u64 << launch_info.c_bit_position
        } else {
            0
        };

    page_tables[launch_info.kernel_pml4e_index as usize] =
        launch_info.kernel_pdpt_paddr | 0x63 | confidentiality_mask;

    // If this platform uses a confidentiality mask, then update the kernel
    // page tables now.
    if confidentiality_mask != 0 {
        update_kernel_page_tables(launch_info, confidentiality_mask);
    }

    // Obtain a reference to the kernel launch parameters in the kernel address
    // space.
    // SAFETY: the boot loader launch parameters supply the correct virtual
    // address of the kernel launch parameters.
    let kernel_launch_info =
        unsafe { &mut *(launch_info.kernel_launch_info as *mut KernelLaunchInfo) };

    kernel_launch_info.lowmem_page_tables = true;
    kernel_launch_info.vtom = vtom;

    // If this is an SNP system, copy the CPUID page from the boot loader
    // address space into the kernel CPUID page.
    if launch_info.platform_type == u32::from(SvsmPlatformType::Snp) {
        copy_cpuid_page(launch_info, kernel_launch_info);
    }

    // Transition to the kernel.
    // SAFETY: the kernel launch context is correctly specified in the boot
    // loader launch parameters.
    unsafe {
        switch_to_kernel(
            launch_info.kernel_entry,
            launch_info.kernel_stack,
            launch_info.platform_type as u64,
        );
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: raising an undefined instuction exception is always safe.
    unsafe { core::arch::asm!("ud2") }
    unreachable!("");
}

struct Alloc;

// SAFETY: A global allocator is required to satisfy linkage requirements of
// external crates.  However, the bootloader never performs heap allocation.
// Consequently, all methods panic, which is sound.
unsafe impl GlobalAlloc for Alloc {
    /// # Safety
    /// All allocator functions are unsafe.  This one simply panics.
    unsafe fn alloc(&self, _: Layout) -> *mut u8 {
        panic!("");
    }

    /// # Safety
    /// All allocator functions are unsafe.  This one simply panics.
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {
        panic!("");
    }

    /// # Safety
    /// All allocator functions are unsafe.  This one simply panics.
    unsafe fn alloc_zeroed(&self, _: Layout) -> *mut u8 {
        panic!("");
    }

    /// # Safety
    /// All allocator functions are unsafe.  This one simply panics.
    unsafe fn realloc(&self, _: *mut u8, _: Layout, _: usize) -> *mut u8 {
        panic!("");
    }
}

#[global_allocator]
static ALLOC: Alloc = Alloc;
