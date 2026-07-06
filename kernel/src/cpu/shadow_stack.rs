// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Coconut-SVSM authors
//
// Author: Tom Dohrmann <erbse.13@gmx.de>

use crate::address::{Address, VirtAddr};

use crate::mm::{PAGE_SIZE, PageRef};
use core::sync::atomic::{AtomicBool, Ordering};

use bitflags::bitflags;

use super::msr::read_msr;

pub const S_CET: u32 = 0x6a2;
pub const PL0_SSP: u32 = 0x6a4;
pub const ISST_ADDR: u32 = 0x6a8;

pub const MODE_64BIT: usize = 1;
pub const BUSY: usize = 1;

pub static IS_CET_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static IS_CET_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set_cet_ss_enabled() {
    IS_CET_ENABLED.store(true, Ordering::Relaxed);
}

/// Returns whether shadow stacks are currently enabled.
#[inline(always)]
pub fn is_cet_ss_enabled() -> bool {
    IS_CET_ENABLED.load(Ordering::Relaxed)
}

pub fn shadow_stack_info() {
    log::info!(
        "Kernel shadow stacks {}",
        match is_cet_ss_enabled() {
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
    ($token_addr:ident) => {{
        use core::arch::asm;

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
                token_addr = in(reg) $token_addr.bits(),
                token_val = in(reg) $token_addr.bits() + 8 + MODE_64BIT,
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
        exit_return: usize,
        /// Whether there is an iret frame on the bottom of the stack.
        iret_frame: bool,
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

struct ShadowStackInitializer<'a> {
    page: &'a PageRef,
    top_of_stack: VirtAddr,
    stack_ptr: usize,
}

impl<'a> ShadowStackInitializer<'a> {
    fn new(page: &'a PageRef, top_of_stack: VirtAddr) -> Self {
        Self {
            page,
            top_of_stack,
            stack_ptr: PAGE_SIZE,
        }
    }

    fn push(&mut self, value: usize) {
        let buf = value.to_ne_bytes();
        self.stack_ptr -= buf.len();
        self.page.write(self.stack_ptr, &buf);
    }

    fn push_token(&mut self, offset: usize, mask: usize) -> VirtAddr {
        let token_offset = PAGE_SIZE - self.stack_ptr + size_of::<usize>();
        let token_addr = self.top_of_stack - token_offset;
        let token = (token_addr + offset).bits() | mask;
        self.push(token);
        token_addr
    }
}

pub fn init_shadow_stack(
    page: &PageRef,
    top_of_sstack: VirtAddr,
    init: ShadowStackInit,
) -> (Option<VirtAddr>, VirtAddr) {
    // Initialize the shadow stack.
    let mut shadow_stack = ShadowStackInitializer::new(page, top_of_sstack);
    match init {
        ShadowStackInit::Normal {
            entry_return,
            exit_return,
            iret_frame,
        } => {
            let base_token_addr = match iret_frame {
                true => Some(shadow_stack.push_token(0, BUSY)),
                false => Some(top_of_sstack - 8),
            };

            shadow_stack.push(exit_return);
            shadow_stack.push(entry_return);

            let token_addr = shadow_stack.push_token(size_of::<usize>(), MODE_64BIT);

            (base_token_addr, token_addr)
        }
        ShadowStackInit::ContextSwitch => {
            let token_addr = shadow_stack.push_token(size_of::<usize>(), MODE_64BIT);
            (None, token_addr)
        }
        ShadowStackInit::Exception => {
            let token_addr = shadow_stack.push_token(0, 0);
            (None, token_addr)
        }
        ShadowStackInit::Init => (None, top_of_sstack - 8),
    }
}
