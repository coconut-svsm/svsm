// SPDX-License-Identifier: MIT OR Apache-2.0

use core::{
    arch::asm,
    sync::atomic::{AtomicBool, Ordering},
};

use bitflags::bitflags;

use super::msr::read_msr;

pub const S_CET: u32 = 0x6a2;
pub const PL0_SSP: u32 = 0x6a4;
pub const ISST_ADDR: u32 = 0x6a8;

pub const MODE_64BIT: usize = 1;

pub static IS_CET_SUPPORTED: AtomicBool = AtomicBool::new(false);

// Try to enable the CET feature in CR4 and set `IS_CET_SUPPORTED` if successful.
pub fn determine_cet_support() {
    let rcx: u64;
    // SAFETY: Inline assembly to enable CET bit in CR4, which does not change
    // any state related to memory safety.
    unsafe {
        asm!(// Try to enable CET in CR4.
             "   mov %cr4, %rax",
             "   or $1<<23, %rax",
             "1: mov %rax, %cr4",
             "   xorq %rcx, %rcx",
             "2:",
             ".pushsection \"__exception_table\",\"a\"",
             ".balign 16",
             ".quad (1b)",
             ".quad (2b)",
             ".popsection",
             out("rax") _,
             out("rcx") rcx,
             options(att_syntax, nostack, nomem, pure, preserves_flags));
    }

    IS_CET_SUPPORTED.store(rcx == 0, Ordering::Relaxed);
}

/// Returns whether shadow stacks are supported by the CPU and the kernel.
#[inline(always)]
pub fn is_cet_ss_supported() -> bool {
    // In theory CPUs can have support for CET, but not CET_SS, but in practice
    // no such CPUs exist. Treat CET being supported as CET_SS being supported.
    IS_CET_SUPPORTED.load(Ordering::Relaxed)
}

/// Enable shadow stacks.
///
/// This code is placed in a macro instead of a function so that we don't have
/// to set up the shadow stack to return from this code.
#[macro_export]
macro_rules! enable_shadow_stacks {
    ($bsp_percpu:ident) => {{
        use core::arch::asm;

        let token_addr = $bsp_percpu.get_top_of_shadow_stack();

        unsafe {
            asm!(
                // Enable shadow stacks.
                "wrmsr",
                // Write a shadow stack restore token onto the stack.
                "wrssq [{token_addr}], {token_val}",
                // Load the shadow stack.
                "rstorssp [{token_addr}]",
                in("ecx") S_CET,
                in("edx") 0,
                in("eax") SCetFlags::SH_STK_EN.bits() | SCetFlags::WR_SHSTK_EN.bits(),
                token_addr = in(reg) token_addr.bits(),
                token_val = in(reg) token_addr.bits() + 8 + MODE_64BIT,
                options(nostack, readonly),
            );
        }
    }};
}

pub fn read_s_cet() -> SCetFlags {
    SCetFlags::from_bits_retain(read_msr(S_CET))
}

bitflags! {
    pub struct SCetFlags: u64 {
        const SH_STK_EN = 1 << 0; // Enables the shadow stacks
        const WR_SHSTK_EN = 1 << 1; // Enables the WRSS instruction
    }
}
