// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) Coconut-SVSM authors

//! Owned CPU startup state and local initialization.

use super::isst::load_isst;
use super::percpu::PerCpu;
use super::percpu::PerCpuShared;
use super::shadow_stack::is_cet_ss_enabled;
use super::tss::load_gdt_tss;
use crate::address::{Address, VirtAddr};
use crate::error::SvsmError;
use crate::hyperv;
use crate::mm::PageBox;
use crate::mm::pagetable::{PageTable, load_initial_pgtable};
use crate::platform::SvsmPlatform;
use crate::task::set_current_stack;
use crate::utils::MemoryRegion;

/// Owned resources handed from CPU preparation to the target CPU.
#[derive(Debug)]
pub struct CpuLaunch {
    percpu: &'static PerCpu,
    shared: &'static PerCpuShared,
    pgtable: PageBox<PageTable>,
    context_switch_stack: VirtAddr,
    init_shadow_stack: Option<VirtAddr>,
    current_stack: MemoryRegion<VirtAddr>,
}

impl CpuLaunch {
    pub fn new(
        percpu: &'static PerCpu,
        shared: &'static PerCpuShared,
        pgtable: PageBox<PageTable>,
        context_switch_stack: VirtAddr,
        init_shadow_stack: Option<VirtAddr>,
        current_stack: MemoryRegion<VirtAddr>,
    ) -> Self {
        Self {
            percpu,
            shared,
            pgtable,
            context_switch_stack,
            init_shadow_stack,
            current_stack,
        }
    }

    pub fn new_application(
        percpu: &'static PerCpu,
        shared: &'static PerCpuShared,
        pgtable: PageBox<PageTable>,
        context_switch_stack: VirtAddr,
        init_shadow_stack: Option<VirtAddr>,
    ) -> Self {
        let current_stack = MemoryRegion::new(
            context_switch_stack
                .checked_sub(crate::mm::STACK_SIZE)
                .unwrap(),
            crate::mm::STACK_SIZE,
        );
        Self::new(
            percpu,
            shared,
            pgtable,
            context_switch_stack,
            init_shadow_stack,
            current_stack,
        )
    }

    pub fn percpu(&self) -> &'static PerCpu {
        self.percpu
    }

    pub fn shared(&self) -> &'static PerCpuShared {
        self.shared
    }

    pub fn pgtable(&self) -> &PageTable {
        &self.pgtable
    }

    pub fn context_switch_stack(&self) -> VirtAddr {
        self.context_switch_stack
    }

    pub fn get_initial_context(&self, start_rip: u64) -> hyperv::HvInitialVpContext {
        self.percpu
            .get_initial_context(start_rip, &self.pgtable, self.context_switch_stack)
    }
}

/// Initialize state which must be installed by the CPU that owns it.
pub fn initialize_cpu(launch: CpuLaunch, platform: &dyn SvsmPlatform) -> Result<(), SvsmError> {
    let percpu = launch.percpu;
    let pgtable = PageBox::leak(launch.pgtable);
    percpu.setup_percpu_keys(
        launch.shared,
        pgtable,
        launch.context_switch_stack,
        launch.init_shadow_stack,
    );

    // SAFETY: the per-CPU virtual range, stack, TSS, and ISST have been
    // populated in this page table before the CPU is allowed to use it.
    unsafe { load_initial_pgtable() };

    load_gdt_tss(true);

    if is_cet_ss_enabled() {
        load_isst();
    }

    set_current_stack(launch.current_stack);
    percpu.setup_on_cpu(platform)
}
