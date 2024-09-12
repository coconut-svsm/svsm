// SPDX-License-Identifier: MIT OR Apache-2.0

use bitflags::bitflags;

use super::msr::read_msr;

pub const S_CET: u32 = 0x6a2;
pub const PL0_SSP: u32 = 0x6a4;
pub const ISST_ADDR: u32 = 0x6a8;

pub const MODE_64BIT: usize = 1;

/// Enable shadow stacks.
///
/// This code is placed in a macro instead of a function so that we don't have
/// to set up the shadow stack to return from this code.
#[macro_export]
macro_rules! enable_shadow_stacks {
    ($bsp_percpu:ident) => {{
        use core::arch::asm;
        use core::assert;
        use svsm::address::Address;
        use svsm::cpu::control_regs::{read_cr4, write_cr4, CR4Flags};
        use svsm::cpu::shadow_stack::{SCetFlags, MODE_64BIT, S_CET};

        let token_addr = $bsp_percpu.get_top_of_shadow_stack();

        // Enable CET in CR4.
        let mut cr4 = read_cr4();
        assert!(!cr4.contains(CR4Flags::CET), "CET is already enabled");
        cr4 |= CR4Flags::CET;
        write_cr4(cr4);

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
