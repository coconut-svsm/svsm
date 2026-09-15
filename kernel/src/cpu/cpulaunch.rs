// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) Coconut-SVSM authors

//! Owned CPU startup state and local initialization.

use super::isst::load_isst;
use super::percpu::PerCpu;
use super::shadow_stack::is_cet_ss_enabled;
use super::tss::load_gdt_tss;
use crate::address::{Address, VirtAddr};
use crate::error::SvsmError;
use crate::platform::SvsmPlatform;
use crate::task::set_current_stack;
use crate::utils::MemoryRegion;

/// Owned resources handed from CPU preparation to the target CPU.
#[derive(Debug)]
pub struct CpuLaunch {
    percpu: &'static PerCpu,
    current_stack: MemoryRegion<VirtAddr>,
}

impl CpuLaunch {
    pub fn new(percpu: &'static PerCpu, current_stack: MemoryRegion<VirtAddr>) -> Self {
        Self {
            percpu,
            current_stack,
        }
    }

    pub fn new_application(percpu: &'static PerCpu) -> Self {
        let top_of_stack = percpu.get_top_of_context_switch_stack().unwrap();
        let current_stack = MemoryRegion::new(
            top_of_stack.checked_sub(crate::mm::STACK_SIZE).unwrap(),
            crate::mm::STACK_SIZE,
        );
        Self::new(percpu, current_stack)
    }

    pub fn percpu(&self) -> &'static PerCpu {
        self.percpu
    }
}

/// Initialize state which must be installed by the CPU that owns it.
pub fn initialize_cpu(launch: CpuLaunch, platform: &dyn SvsmPlatform) -> Result<(), SvsmError> {
    let percpu = launch.percpu;
    percpu.setup_percpu_keys();

    // SAFETY: the per-CPU virtual range, stack, TSS, and ISST have been
    // populated in this page table before the CPU is allowed to use it.
    unsafe { percpu.get_pgtable().load() };

    load_gdt_tss(true);

    if is_cet_ss_enabled() {
        load_isst();
    }

    set_current_stack(launch.current_stack);
    percpu.setup_on_cpu(platform)
}
