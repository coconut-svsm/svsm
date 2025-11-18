// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>

extern crate alloc;

use crate::{
    address::{Address, VirtAddr},
    cpu::idt::common::{is_exception_handler_return_site, X86ExceptionContext},
    cpu::percpu::try_this_cpu,
    mm::{STACK_SIZE, STACK_TOTAL_SIZE, SVSM_CONTEXT_SWITCH_STACK, SVSM_STACK_IST_DF_BASE},
    utils::MemoryRegion,
};
use alloc::format;
use bootlib::kernel_launch::{STAGE2_STACK, STAGE2_STACK_END};
use core::{arch::asm, mem};

extern "C" {
    static bsp_stack: u64;
    static bsp_stack_end: u64;
}

#[derive(Clone, Copy, Debug, Default)]
struct StackFrame {
    rbp: VirtAddr,
    rsp: VirtAddr,
    rip: VirtAddr,
    is_aligned: bool,
    is_last: bool,
    is_exception_frame: bool,
    _stack_depth: usize, // Not needed for frame unwinding, only as diagnostic information.
}

#[derive(Clone, Copy, Debug)]
enum UnwoundStackFrame {
    Valid(StackFrame),
    Invalid,
}

type StacksBounds = [MemoryRegion<VirtAddr>; 3];

#[derive(Debug)]
struct StackUnwinder {
    next_frame: Option<UnwoundStackFrame>,
    stacks: StacksBounds,
}

fn is_stage2() -> bool {
    // If the storage for the default BSP stack pointers lands under 16MB,
    // we're in Stage2.
    (&raw const bsp_stack_end as usize) < (16 << 20)
}

impl StackUnwinder {
    pub fn unwind_this_cpu() -> Self {
        let mut rbp: usize;
        // SAFETY: Inline assembly to read RBP, which does not change any state
        // related to memory safety.
        unsafe {
            asm!("movq %rbp, {}", out(reg) rbp,
                 options(att_syntax));
        };

        let stacks: StacksBounds = if let Some(cpu) = try_this_cpu() {
            let current_stack = cpu.get_current_stack();
            let cs_stack = cpu
                .get_top_of_context_switch_stack()
                .map_or(MemoryRegion::new(VirtAddr::null(), 0), |tos| {
                    MemoryRegion::from_addresses(tos - STACK_SIZE, tos)
                });
            let df_stack = cpu
                .get_top_of_df_stack()
                .map_or(MemoryRegion::new(VirtAddr::null(), 0), |tos| {
                    MemoryRegion::from_addresses(tos - STACK_SIZE, tos)
                });
            [current_stack, cs_stack, df_stack]
        } else {
            // Use default stack addresses.
            if is_stage2() {
                let bsp_init_stack = MemoryRegion::from_addresses(
                    VirtAddr::from(STAGE2_STACK_END as u64),
                    VirtAddr::from(STAGE2_STACK as u64),
                );
                let no_stack = MemoryRegion::new(VirtAddr::null(), 0);
                [bsp_init_stack, no_stack, no_stack]
            } else {
                // SAFETY: the stack addresses are initialied early and can
                // safely be used here.
                let bsp_init_stack = unsafe {
                    MemoryRegion::from_addresses(
                        VirtAddr::from(bsp_stack),
                        VirtAddr::from(bsp_stack_end),
                    )
                };
                let cs_stack = MemoryRegion::new(SVSM_CONTEXT_SWITCH_STACK, STACK_TOTAL_SIZE);
                let df_stack = MemoryRegion::new(SVSM_STACK_IST_DF_BASE, STACK_TOTAL_SIZE);
                [bsp_init_stack, cs_stack, df_stack]
            }
        };

        Self::new(VirtAddr::from(rbp), stacks)
    }

    fn new(rbp: VirtAddr, stacks: StacksBounds) -> Self {
        let first_frame = Self::unwind_framepointer_frame(rbp, &stacks);
        Self {
            next_frame: Some(first_frame),
            stacks,
        }
    }

    fn check_unwound_frame(
        rbp: VirtAddr,
        rsp: VirtAddr,
        rip: VirtAddr,
        stacks: &StacksBounds,
    ) -> UnwoundStackFrame {
        // The next frame's rsp or rbp should live on some valid stack,
        // otherwise mark the unwound frame as invalid.
        let Some(stack) = stacks.iter().find(|stack| {
            !stack.is_empty() && (stack.contains_inclusive(rsp) || stack.contains_inclusive(rbp))
        }) else {
            log::info!("check_unwound_frame: rsp {rsp:#018x} and rbp {rbp:#018x} does not match any known stack");
            return UnwoundStackFrame::Invalid;
        };

        // The x86-64 ABI requires stack frames to be 16b-aligned
        let is_aligned = rbp.is_aligned(16);
        let is_last = Self::frame_is_last(rbp);
        let is_exception_frame = is_exception_handler_return_site(rip);

        if !is_last && !is_exception_frame {
            // Consistency check to ensure forward-progress: never unwind downwards.
            if rbp < rsp {
                return UnwoundStackFrame::Invalid;
            }
        }

        let _stack_depth = stack.end() - rsp;

        UnwoundStackFrame::Valid(StackFrame {
            rbp,
            rsp,
            rip,
            is_aligned,
            is_last,
            is_exception_frame,
            _stack_depth,
        })
    }

    fn unwind_framepointer_frame(rbp: VirtAddr, stacks: &StacksBounds) -> UnwoundStackFrame {
        let rsp = rbp;

        // Storage for return address + saved %rbp
        let Some(range) = MemoryRegion::checked_new(rsp, 2 * mem::size_of::<VirtAddr>()) else {
            return UnwoundStackFrame::Invalid;
        };

        if !stacks.iter().any(|stack| stack.contains_region(&range)) {
            return UnwoundStackFrame::Invalid;
        }

        // Saved %rbp
        //
        // SAFETY: This function always works on the stacks of the current
        // context, so de-referencing pointers from the stacks of the context
        // is safe.
        let rbp = unsafe { rsp.as_ptr::<VirtAddr>().read_unaligned() };
        let rsp = rsp + mem::size_of::<VirtAddr>();
        // Return address
        //
        // SAFETY: This function always works on the stacks of the current
        // context, so de-referencing pointers from the stacks of the context
        // is safe.
        let rip = unsafe { rsp.as_ptr::<VirtAddr>().read_unaligned() };
        let rsp = rsp + mem::size_of::<VirtAddr>();

        Self::check_unwound_frame(rbp, rsp, rip, stacks)
    }

    fn unwind_exception_frame(rsp: VirtAddr, stacks: &StacksBounds) -> UnwoundStackFrame {
        let Some(range) = MemoryRegion::checked_new(rsp, mem::size_of::<X86ExceptionContext>())
        else {
            return UnwoundStackFrame::Invalid;
        };

        if !stacks.iter().any(|stack| stack.contains_region(&range)) {
            return UnwoundStackFrame::Invalid;
        }

        // SAFETY: rsp is in a valid memory range as checked previously
        // in this function. It is always properly aligned because
        // X86ExceptionContext is packed(1). It's in the per-CPU stack
        // so no aliasing can occur.
        let Some(ctx) = (unsafe { rsp.as_ptr::<X86ExceptionContext>().as_ref() }) else {
            return UnwoundStackFrame::Invalid;
        };
        let rbp = VirtAddr::from(ctx.regs.rbp);
        let rip = VirtAddr::from(ctx.frame.rip);
        let rsp = VirtAddr::from(ctx.frame.rsp);

        Self::check_unwound_frame(rbp, rsp, rip, stacks)
    }

    fn frame_is_last(rbp: VirtAddr) -> bool {
        // A new task is launched with RBP = 0, which is pushed onto the stack
        // immediately and can serve as a marker when the end of the stack has
        // been reached.
        rbp == VirtAddr::null()
    }
}

impl Iterator for StackUnwinder {
    type Item = UnwoundStackFrame;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.next_frame;
        match cur {
            Some(cur) => {
                match &cur {
                    UnwoundStackFrame::Invalid => {
                        self.next_frame = None;
                    }
                    UnwoundStackFrame::Valid(cur_frame) => {
                        if cur_frame.is_last {
                            self.next_frame = None
                        } else if cur_frame.is_exception_frame {
                            self.next_frame =
                                Some(Self::unwind_exception_frame(cur_frame.rsp, &self.stacks));
                        } else {
                            self.next_frame =
                                Some(Self::unwind_framepointer_frame(cur_frame.rbp, &self.stacks));
                        }
                    }
                };

                Some(cur)
            }
            None => None,
        }
    }
}

fn print_stack_frame(frame: StackFrame) {
    let mut annotated = false;
    let mut msg = format!("  [{:016x}]", frame.rip);

    if frame.is_exception_frame {
        msg.push_str(" @");
        annotated = true;
    }
    if !frame.is_aligned {
        msg.push_str(if annotated { "#" } else { " #" });
    }
    log::info!("{}", msg);
}

pub fn print_stack(skip: usize) {
    let unwinder = StackUnwinder::unwind_this_cpu();
    log::info!("---BACKTRACE---:");
    for frame in unwinder.skip(skip) {
        match frame {
            UnwoundStackFrame::Valid(item) => print_stack_frame(item),
            UnwoundStackFrame::Invalid => log::info!("  Invalid frame"),
        }
    }
    log::info!("---END---");
}
