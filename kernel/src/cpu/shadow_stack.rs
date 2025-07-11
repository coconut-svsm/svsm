// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Coconut-SVSM authors
//
// Author: Tom Dohrmann <erbse.13@gmx.de>

use crate::address::{Address, VirtAddr};
use crate::platform::SvsmPlatform;

use crate::mm::{PageRef, PAGE_SIZE};
use core::sync::atomic::{AtomicBool, Ordering};

use bitflags::bitflags;

use super::cpuid::CpuidResult;
use super::msr::read_msr;

pub const S_CET: u32 = 0x6a2;
pub const PL0_SSP: u32 = 0x6a4;
pub const ISST_ADDR: u32 = 0x6a8;

pub const MODE_64BIT: usize = 1;
pub const BUSY: usize = 1;

pub static IS_CET_SUPPORTED: AtomicBool = AtomicBool::new(false);

// Try to enable the CET feature in CR4 and set `IS_CET_SUPPORTED` if successful.
pub fn determine_cet_support(platform: &dyn SvsmPlatform) {
    if platform.determine_cet_support() {
        IS_CET_SUPPORTED.store(true, Ordering::Relaxed);
    }
}

pub fn determine_cet_support_from_cpuid() -> bool {
    let cpuid = CpuidResult::get(7, 0);
    (cpuid.ecx & 0x80) != 0
}

/// Returns whether shadow stacks are supported by the CPU and the kernel.
#[inline(always)]
pub fn is_cet_ss_supported() -> bool {
    // In theory CPUs can have support for CET, but not CET_SS, but in practice
    // no such CPUs exist. Treat CET being supported as CET_SS being supported.
    IS_CET_SUPPORTED.load(Ordering::Relaxed)
}

pub fn shadow_stack_info() {
    log::info!(
        "Kernel shadow stacks {}",
        match is_cet_ss_supported() {
            true => "enabled",
            false => "not supported",
        }
    );
}

/// Enable shadow stacks.
///
/// This code is placed in a macro instead of a function so that we don't have
/// to set up the shadow stack to return from this code.
#[macro_export]
macro_rules! enable_shadow_stacks {
    ($bsp_percpu:ident) => {{
        use core::arch::asm;

        let token_addr = $bsp_percpu.get_top_of_shadow_stack().unwrap();

        // SAFETY: This assembly enables shadow-stacks and does not impact Rust
        // memory safety.
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

#[derive(Debug)]
pub enum ShadowStackInit {
    /// The initial shadow stack used by a CPU.
    ///
    /// This won't place any tokens on the shadow stack.
    Init,
    /// A shadow stack to be used during normal execution of a task.
    ///
    /// This will create a shadow stack with a shadow stack restore token.
    Normal {
        /// The address of the first instruction that will be executed by the task.
        entry_return: usize,
        /// The address of the function that's executed when the task exits.
        exit_return: Option<usize>,
    },
    /// A shadow stack to be used during context switches.
    ///
    /// This will create a shadow stack with a shadow stack restore token.
    ContextSwitch,
    /// A shadow stack to be used for exception handling (either in PL0_SSP or
    /// in the ISST).
    ///
    /// This will create a shadow stack with a supervisor shadow stack token.
    Exception,
}

pub fn init_shadow_stack(
    page: &PageRef,
    top_of_sstack: VirtAddr,
    init: ShadowStackInit,
) -> (Option<VirtAddr>, VirtAddr) {
    // Initialize the shadow stack.
    let mut chunk = [0; 24];
    let (base_token_addr, ssp) = match init {
        ShadowStackInit::Normal {
            entry_return,
            exit_return,
        } => {
            // If exit return is empty, then this thread will be used as a
            // user task stack.  In that case, place a busy token at the
            // base of the shadow stack.
            let base_token_addr = top_of_sstack - 8;
            let base_token = match exit_return {
                Some(addr) => addr,
                None => base_token_addr.bits() + BUSY,
            };

            let (token_bytes, rip_bytes) = chunk.split_at_mut(8);

            // Create a shadow stack restore token.
            let token_addr = top_of_sstack - 24;
            let token = (token_addr + 8).bits() + MODE_64BIT;
            token_bytes.copy_from_slice(&token.to_ne_bytes());

            let (entry_bytes, base_bytes) = rip_bytes.split_at_mut(8);
            entry_bytes.copy_from_slice(&entry_return.to_ne_bytes());
            base_bytes.copy_from_slice(&base_token.to_ne_bytes());

            (Some(base_token_addr), token_addr)
        }
        ShadowStackInit::ContextSwitch => {
            let (_, token_bytes) = chunk.split_at_mut(16);

            // Create a shadow stack restore token.
            let token_addr = top_of_sstack - 8;
            let token = (token_addr + 8).bits() + MODE_64BIT;
            token_bytes.copy_from_slice(&token.to_ne_bytes());

            (None, token_addr)
        }
        ShadowStackInit::Exception => {
            let (_, token_bytes) = chunk.split_at_mut(16);

            // Create a supervisor shadow stack token.
            let token_addr = top_of_sstack - 8;
            let token = token_addr.bits();
            token_bytes.copy_from_slice(&token.to_ne_bytes());

            (None, token_addr)
        }
        ShadowStackInit::Init => (None, top_of_sstack - 8),
    };

    page.write(PAGE_SIZE - chunk.len(), &chunk);

    (base_token_addr, ssp)
}
