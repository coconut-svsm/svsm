// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::mm::stack::{allocate_stack, stack_base_pointer};
use crate::cpu::msr::{write_msr, MSR_GS_BASE};
use crate::mm::alloc::allocate_page;
use super::tss::{X86Tss, IST_DF};
use crate::types::VirtAddr;
use super::gdt::load_tss;
use crate::sev::GHCB;
use core::arch::asm;
use core::ptr;

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
    tss     : X86Tss,
}

impl PerCpu {
    pub const fn new() -> Self {
        PerCpu {
            ghcb    : ptr::null_mut(),
            ist     : IstStacks::new(),
            tss     : X86Tss::new(),
        }
    }

    pub fn setup_ghcb(&mut self) -> Result<(), ()> {
        let ghcb_page = allocate_page().expect("Failed to allocate GHCB page");
        self.ghcb = ghcb_page as *mut GHCB;
        unsafe { (*self.ghcb).init() }
    }

    fn setup_tss(&mut self) {
        self.tss.ist_stacks[IST_DF] = stack_base_pointer(self.ist.double_fault_stack);
        load_tss(&self.tss);
    }

    pub fn set_gs_base(&self) {
        let gs_base : u64 = (self as *const PerCpu) as u64;
        write_msr(MSR_GS_BASE, gs_base);
    }

    pub fn setup(&mut self) -> Result<(), ()> {
        // Setup GHCB
        self.setup_ghcb()?;

        // Allocate IST stacks
        self.ist.allocate_stacks()?;

        // Setup TSS
        self.setup_tss();

        // Write GS_BASE
        self.set_gs_base();

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
