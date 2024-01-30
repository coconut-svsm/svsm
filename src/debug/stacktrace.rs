// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>

use crate::{
    address::{Address, VirtAddr},
    cpu::idt::common::{is_exception_handler_return_site, X86ExceptionContext},
    cpu::percpu::this_cpu,
    mm::address_space::STACK_SIZE,
    mm::stack::StackBounds,
};
use core::{arch::asm, mem};

#[derive(Clone, Copy, Debug, Default)]
struct StackFrame {
    rbp: VirtAddr,
    rsp: VirtAddr,
    rip: VirtAddr,
    is_last: bool,
    is_exception_frame: bool,
    _stack_depth: usize, // Not needed for frame unwinding, only as diagnostic information.
}

#[derive(Clone, Copy, Debug)]
enum UnwoundStackFrame {
    Valid(StackFrame),
    Invalid,
}

type StacksBounds = [StackBounds; 3];

#[derive(Debug)]
struct StackUnwinder {
    next_frame: Option<UnwoundStackFrame>,
    stacks: StacksBounds,
}

impl StackUnwinder {
    pub fn unwind_this_cpu() -> Self {
        let mut rbp: usize;
        unsafe {
            asm!("movq %rbp, {}", out(reg) rbp,
                 options(att_syntax));
        };

        let top_of_init_stack = this_cpu().get_top_of_stack();
        let top_of_df_stack = this_cpu().get_top_of_df_stack();

        let stacks: StacksBounds = [
            StackBounds {
                bottom: top_of_init_stack - STACK_SIZE,
                top: top_of_init_stack,
            },
            StackBounds {
                bottom: top_of_df_stack - STACK_SIZE,
                top: top_of_df_stack,
            },
            this_cpu().current_stack,
        ];

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
        // The next frame's rsp should live on some valid stack, otherwise mark
        // the unwound frame as invalid.
        let stack = match stacks.iter().find(|stack| stack.range_is_on_stack(rsp, 0)) {
            Some(stack) => stack,
            None => {
                return UnwoundStackFrame::Invalid;
            }
        };

        let is_last = Self::frame_is_last(rbp, rip, stacks);
        let is_exception_frame = is_exception_handler_return_site(rip);

        if !is_last && !is_exception_frame {
            // Consistency check to ensure forward-progress: never unwind downwards.
            if rbp < rsp {
                return UnwoundStackFrame::Invalid;
            }
        }

        let _stack_depth = stack.top - rsp;

        UnwoundStackFrame::Valid(StackFrame {
            rbp,
            rip,
            rsp,
            is_last,
            is_exception_frame,
            _stack_depth,
        })
    }

    fn unwind_framepointer_frame(rbp: VirtAddr, stacks: &StacksBounds) -> UnwoundStackFrame {
        let rsp = rbp;

        if !stacks
            .iter()
            .any(|stack| stack.range_is_on_stack(rsp, 2 * mem::size_of::<VirtAddr>()))
        {
            return UnwoundStackFrame::Invalid;
        }

        let rbp = unsafe { rsp.as_ptr::<VirtAddr>().read_unaligned() };
        let rsp = rsp + mem::size_of::<VirtAddr>();
        let rip = unsafe { rsp.as_ptr::<VirtAddr>().read_unaligned() };
        let rsp = rsp + mem::size_of::<VirtAddr>();

        Self::check_unwound_frame(rbp, rsp, rip, stacks)
    }

    fn unwind_exception_frame(rsp: VirtAddr, stacks: &StacksBounds) -> UnwoundStackFrame {
        if !stacks
            .iter()
            .any(|stack| stack.range_is_on_stack(rsp, mem::size_of::<X86ExceptionContext>()))
        {
            return UnwoundStackFrame::Invalid;
        }

        let ctx = unsafe { &*rsp.as_ptr::<X86ExceptionContext>() };
        let rbp = VirtAddr::from(ctx.regs.rbp);
        let rip = VirtAddr::from(ctx.frame.rip);
        let rsp = VirtAddr::from(ctx.frame.rsp);

        Self::check_unwound_frame(rbp, rsp, rip, stacks)
    }

    fn frame_is_last(rbp: VirtAddr, _rip: VirtAddr, stacks: &StacksBounds) -> bool {
        // The BSP's and secondary APs' Rust entry points are getting jumped to
        // with rsp set to the top of the respective runtime stack each. First
        // thing they'd do when compiled with frame pointers enabled is to push
        // some garbage rbp and 'movq rsp, rbp' afterwards. That is, their rbp
        // would point to the word at the top of the runtime stack.
        stacks.iter().any(|stack| {
            let word_size = mem::size_of::<VirtAddr>();
            stack.top.checked_sub(word_size) == Some(rbp)
        })
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

pub fn print_stack(skip: usize) {
    let unwinder = StackUnwinder::unwind_this_cpu();
    log::info!("---BACKTRACE---:");
    for frame in unwinder.skip(skip) {
        match frame {
            UnwoundStackFrame::Valid(item) => log::info!("  [{:#018x}]", item.rip),
            UnwoundStackFrame::Invalid => log::info!("  Invalid frame"),
        }
    }
    log::info!("---END---");
}
