// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::mm::stack::{allocate_stack, stack_base_pointer};
use crate::cpu::msr::{write_msr, MSR_GS_BASE};
use crate::types::{VirtAddr, MAX_CPUS};
use crate::mm::alloc::allocate_page;
use super::tss::{X86Tss, IST_DF};
use crate::sev::ghcb::GHCB;
use super::gdt::load_tss;
use core::arch::asm;
use core::ptr;

static mut PER_CPU_PTRS : [usize; MAX_CPUS] = [0; MAX_CPUS];

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

    pub fn setup(&mut self) -> Result<(), ()> {
        // Setup GHCB
        self.setup_ghcb()?;

        // Allocate IST stacks
        self.ist.allocate_stacks()?;

        // Setup TSS
        self.setup_tss();

        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), ()> {
        if self.ghcb == ptr::null_mut() {
            return Ok(());
        }

        unsafe { (*self.ghcb).shutdown() }
    }

    pub fn ghcb(&mut self) -> &'static mut GHCB {
        unsafe { self.ghcb.as_mut().unwrap() }
    }
}

unsafe impl Sync for PerCpu { }

pub fn register_per_cpu(cpu : usize, per_cpu : &PerCpu) {
    unsafe {
        assert!(PER_CPU_PTRS[cpu] == 0);
        PER_CPU_PTRS[cpu] = (per_cpu as *const PerCpu) as usize;
    }
}

pub fn load_per_cpu(cpu : usize) {
    unsafe {
        assert!(PER_CPU_PTRS[cpu] != 0);
        let gs_base = (&PER_CPU_PTRS[cpu] as *const usize) as u64;
        write_msr(MSR_GS_BASE, gs_base);
    }
}

#[inline(always)]
unsafe fn this_cpu_ptr() -> usize {
    let ptr : usize;

    asm!("movq %gs:0, %rax", out("rax") ptr, options(att_syntax));

    ptr
}

pub fn this_cpu() -> &'static PerCpu {
    unsafe {
        let this_cpu_ptr = this_cpu_ptr();
        (this_cpu_ptr as *mut PerCpu).as_ref().unwrap()
    }
}

pub fn this_cpu_mut() -> &'static mut PerCpu {
    unsafe {
        let this_cpu_ptr = this_cpu_ptr();
        (this_cpu_ptr as *mut PerCpu).as_mut().unwrap()
    }
}
