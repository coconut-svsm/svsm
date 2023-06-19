// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use core::arch::{asm, global_asm};
use core::mem::size_of;
use core::sync::atomic::{AtomicU32, Ordering};

use alloc::boxed::Box;

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::msr::{rdtsc, read_flags};
use crate::cpu::percpu::{this_cpu, this_cpu_mut};
use crate::cpu::{X86GeneralRegs, X86SegmentRegs};
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::alloc::{allocate_pages, get_order};
use crate::mm::pagetable::{get_init_pgtable_locked, PageTable, PageTableRef};
use crate::mm::{
    virt_to_phys, PAGE_SIZE, PGTABLE_LVL3_IDX_PERCPU, SVSM_PERTASK_STACK_BASE,
    SVSM_PERTASK_STACK_TOP,
};
use crate::utils::zero_mem_region;

use super::schedule::schedule;

pub const INITIAL_TASK_ID: u32 = 1;

const STACK_SIZE: usize = 65536;

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum TaskState {
    RUNNING,
    SCHEDULED,
    TERMINATED,
}

pub struct TaskStack {
    pub virt_base: VirtAddr,
    pub virt_top: VirtAddr,
    pub phys: PhysAddr,
}

pub const TASK_FLAG_SHARE_PT: u16 = 0x01;

struct TaskIDAllocator {
    next_id: AtomicU32,
}

impl TaskIDAllocator {
    const fn new() -> Self {
        Self {
            next_id: AtomicU32::new(INITIAL_TASK_ID + 1),
        }
    }

    fn next_id(&self) -> u32 {
        let mut id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // Reserve IDs of 0 and 1
        while (id == 0_u32) || (id == INITIAL_TASK_ID) {
            id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        id
    }
}

static TASK_ID_ALLOCATOR: TaskIDAllocator = TaskIDAllocator::new();

/// This trait is used to implement the strategy that determines
/// how much CPU time a task has been allocated. The task with the
/// lowest runtime value is likely to be the next scheduled task
pub trait TaskRuntime {
    /// Called when a task is allocated to a CPU just before the task
    /// context is restored. The task should start tracking the CPU
    /// execution allocation at this point.
    fn schedule_in(&mut self);

    /// Called by the scheduler at the point the task is interrupted
    /// and marked for deallocation from the CPU. The task should
    /// update the runtime calculation at this point.
    fn schedule_out(&mut self);

    /// Returns whether this is the first time a task has been
    /// considered for scheduling.
    fn first(&self) -> bool;

    /// Overrides the calculated runtime value with the given value.
    /// This can be used to set or adjust the runtime of a task.
    fn set(&mut self, runtime: u64);

    /// Flag the runtime as terminated so the scheduler does not
    /// find terminated tasks before running tasks.
    fn terminated(&mut self);

    /// Returns a value that represents the amount of CPU the task
    /// has been allocated
    fn value(&self) -> u64;
}

/// Tracks task runtime based on the CPU timestamp counter
#[derive(Default)]
#[repr(transparent)]
pub struct TscRuntime {
    runtime: u64,
}

impl TaskRuntime for TscRuntime {
    fn schedule_in(&mut self) {
        self.runtime = rdtsc();
    }

    fn schedule_out(&mut self) {
        self.runtime += rdtsc() - self.runtime;
    }

    fn first(&self) -> bool {
        self.runtime == 0
    }

    fn set(&mut self, runtime: u64) {
        self.runtime = runtime;
    }

    fn terminated(&mut self) {
        self.runtime = u64::MAX;
    }

    fn value(&self) -> u64 {
        self.runtime
    }
}

/// Tracks task runtime based on the number of times the task has been
/// scheduled
#[derive(Default)]
#[repr(transparent)]
pub struct CountRuntime {
    count: u64,
}

impl TaskRuntime for CountRuntime {
    fn schedule_in(&mut self) {
        self.count += 1;
    }

    fn schedule_out(&mut self) {}

    fn first(&self) -> bool {
        self.count == 0
    }

    fn set(&mut self, runtime: u64) {
        self.count = runtime;
    }

    fn terminated(&mut self) {
        self.count = u64::MAX;
    }

    fn value(&self) -> u64 {
        self.count
    }
}

// Define which runtime counter to use
type TaskRuntimeImpl = CountRuntime;

#[repr(C)]
#[derive(Default)]
pub struct TaskContext {
    pub seg: X86SegmentRegs,
    pub regs: X86GeneralRegs,
    pub flags: u64,
    pub ret_addr: u64,
}

#[repr(C)]
pub struct Task {
    pub rsp: u64,

    /// Information about the task stack
    pub stack: TaskStack,

    /// Page table that is loaded when the task is scheduled
    pub page_table: SpinLock<PageTableRef>,

    /// Current state of the task
    pub state: TaskState,

    /// Task affinity
    /// None: The task can be scheduled to any CPU
    /// u32:  The APIC ID of the CPU that the task must run on
    pub affinity: Option<u32>,

    /// ID of the task
    pub id: u32,

    /// Amount of CPU resource the task has consumed
    pub runtime: TaskRuntimeImpl,
}

impl Task {
    pub fn create(entry: extern "C" fn(), flags: u16) -> Result<Box<Task>, SvsmError> {
        let mut pgtable = if (flags & TASK_FLAG_SHARE_PT) != 0 {
            this_cpu().get_pgtable().clone_shared()?
        } else {
            Self::allocate_page_table()?
        };

        let (task_stack, rsp) = Self::allocate_stack(entry, &mut pgtable)?;

        let task: Box<Task> = Box::new(Task {
            rsp: u64::from(rsp),
            stack: task_stack,
            page_table: SpinLock::new(pgtable),
            state: TaskState::RUNNING,
            affinity: None,
            id: TASK_ID_ALLOCATOR.next_id(),
            runtime: TaskRuntimeImpl::default(),
        });
        Ok(task)
    }

    pub fn set_current(&mut self, previous_task: *mut Task) {
        // This function is called by one task but returns in the context of
        // another task. The context of the current task is saved and execution
        // can resume at the point of the task switch, effectively completing
        // the function call for the original task.
        let new_task_addr = (self as *mut Task) as u64;

        // Switch to the new task
        unsafe {
            asm!(
                r#"
                    call switch_context
                "#,
                in("rsi") previous_task as u64,
                in("rdi") new_task_addr,
                options(att_syntax));
        }
    }

    pub fn set_affinity(&mut self, affinity: Option<u32>) {
        self.affinity = affinity;
    }

    fn allocate_stack(
        entry: extern "C" fn(),
        pgtable: &mut PageTableRef,
    ) -> Result<(TaskStack, VirtAddr), SvsmError> {
        let stack_size = SVSM_PERTASK_STACK_TOP - SVSM_PERTASK_STACK_BASE;
        let num_pages = 1 << get_order(STACK_SIZE);
        assert!(stack_size == num_pages * PAGE_SIZE);
        let pages = allocate_pages(get_order(STACK_SIZE))?;
        zero_mem_region(pages, pages + stack_size);

        let task_stack = TaskStack {
            virt_base: VirtAddr::from(SVSM_PERTASK_STACK_BASE),
            virt_top: VirtAddr::from(SVSM_PERTASK_STACK_TOP),
            phys: virt_to_phys(pages),
        };

        // We current have a virtual address in SVSM shared memory for the stack. Configure
        // the per-task pagetable to map the stack into the task memory map.
        pgtable.map_region_4k(
            task_stack.virt_base,
            task_stack.virt_top,
            task_stack.phys,
            PageTable::task_data_flags(),
        )?;

        // We need to setup a context on the stack that matches the stack layout
        // defined in switch_context below.
        let stack_pos = pages + stack_size;
        let stack_ptr = stack_pos.as_mut_ptr() as *mut u64;

        // 'Push' the task frame onto the stack
        unsafe {
            // flags
            stack_ptr.offset(-3).write(read_flags());
            // ret_addr
            stack_ptr.offset(-2).write(entry as *const () as u64);
            // Task termination handler for when entry point returns
            stack_ptr.offset(-1).write(task_exit as *const () as u64);
        }

        let initial_rsp =
            VirtAddr::from(SVSM_PERTASK_STACK_TOP - (size_of::<TaskContext>() + size_of::<u64>()));
        Ok((task_stack, initial_rsp))
    }

    fn allocate_page_table() -> Result<PageTableRef, SvsmError> {
        // Base the new task page table on the initial SVSM kernel page table.
        // When the pagetable is schedule to a CPU, the per CPU entry will also
        // be added to the pagetable.
        get_init_pgtable_locked().clone_shared()
    }
}

extern "C" fn task_exit() {
    // Restrict the scope of the mutable borrow below otherwise when the task context
    // is switched via schedule() the borrow remains in scope.
    {
        let this_task = this_cpu_mut()
            .current_task
            .as_mut()
            .expect("Invalid state in task_exit()");
        let mut current_task = this_task.task.borrow_mut();
        current_task.state = TaskState::TERMINATED;
        // Ensure the scheduler does not waste time encountering terminated tasks
        // by setting a high runtime value
        current_task.runtime.terminated();
    }
    schedule();
}

#[allow(unused)]
#[no_mangle]
extern "C" fn apply_new_context(new_task: *mut Task) -> u64 {
    unsafe {
        let mut pt = (*new_task).page_table.lock();
        pt.copy_entry(&this_cpu().get_pgtable(), PGTABLE_LVL3_IDX_PERCPU);
        pt.cr3_value().bits() as u64
    }
}

global_asm!(
    r#"
        .text

    switch_context:
        // Save the current context. The layout must match the TaskContext structure.
        pushfq
        pushq   %rax
        pushq   %rbx
        pushq   %rcx
        pushq   %rdx
        pushq   %rsi
        pushq   %rdi
        pushq   %rbp
        pushq   %r8
        pushq   %r9
        pushq   %r10
        pushq   %r11
        pushq   %r12
        pushq   %r13
        pushq   %r14
        pushq   %r15
        
        movq    %ss, %rax
        pushq   %rax
        movq    %gs, %rax
        pushq   %rax
        movq    %fs, %rax
        pushq   %rax
        movq    %es, %rax
        pushq   %rax
        movq    %ds, %rax
        pushq   %rax
        movq    %cs, %rax
        pushq   %rax

        // Save the current stack pointer
        testq   %rsi, %rsi
        jz      1f
        movq    %rsp, (%rsi)

    1:
        // Switch to the new task state
        mov     %rdi, %rbx
        call    apply_new_context
        mov     %rax, %cr3

        // Switch to the new task stack
        movq    (%rbx), %rsp

        // Not currently changing segment registers between tasks
        addq        $6*8, %rsp

        popq        %r15
        popq        %r14
        popq        %r13
        popq        %r12
        popq        %r11
        popq        %r10
        popq        %r9
        popq        %r8
        popq        %rbp
        popq        %rdi
        popq        %rsi
        popq        %rdx
        popq        %rcx
        popq        %rbx
        popq        %rax
        popfq

        ret
    "#,
    options(att_syntax)
);
