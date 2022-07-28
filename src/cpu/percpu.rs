// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::cpu::msr::{write_msr, MSR_GS_BASE};
use crate::mm::stack::allocate_stack;
use crate::mm::alloc::allocate_page;
use crate::sev::GHCB;
use crate::types::VirtAddr;
use core::ptr;
use core::arch::asm;

struct IstStacks {
    double_fault_stack : VirtAddr,
}

impl IstStacks {
    const fn new() -> Self {
        IstStacks {
            double_fault_stack : 0,
        }
    }

    pub fn allocate_stacks(&mut self) -> Result<(), ()> {
        self.double_fault_stack = allocate_stack()?;
        Ok(())
    }
}

pub struct PerCpu {
    ghcb    : *mut GHCB,
    ist     : IstStacks,
}

impl PerCpu {
    pub const fn new() -> Self {
        PerCpu {
            ghcb    : ptr::null_mut(),
            ist     : IstStacks::new(),
        }
    }

    pub fn setup(&mut self) -> Result<(), ()> {
        // Setup GHCB
        let ghcb_page = allocate_page().expect("Failed to allocate GHCB page");
        self.ghcb = ghcb_page as *mut GHCB;
        unsafe { (*self.ghcb).init()?; }

        // Allocate IST stacks
        self.ist.allocate_stacks()?;

        // Write GS_BASE
        let gs_base : u64 = (self as *const PerCpu) as u64;
        write_msr(MSR_GS_BASE, gs_base);

        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), ()> {
        if self.ghcb == ptr::null_mut() {
            return Ok(());
        }

        unsafe { (*self.ghcb).shutdown() }
    }
}

unsafe impl Sync for PerCpu { }

pub fn this_cpu_ghcb() -> &'static mut GHCB {
    unsafe {
        // FIXME: Implement proper offset calculation
        let offset = 0;

        let mut ghcb_addr : VirtAddr;

        asm!("movq %gs:(%rax), %rdx", in("rax") offset, out("rdx") ghcb_addr, options(att_syntax));

        (ghcb_addr as *mut GHCB).as_mut().unwrap()
    }
}
