// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::arch::{asm, global_asm};
use core::fmt;
use core::mem::size_of;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::address::{Address, VirtAddr};
use crate::cpu::msr::{rdtsc, read_flags};
use crate::cpu::percpu::{this_cpu, this_cpu_mut};
use crate::cpu::X86GeneralRegs;
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::pagetable::{get_init_pgtable_locked, PTEntryFlags, PageTableRef};
use crate::mm::vm::{Mapping, VMKernelStack, VMUserStack, VMR};
use crate::mm::{
    PAGE_SIZE, SVSM_PERTASK_BASE, SVSM_PERTASK_BASE_CPL3, SVSM_PERTASK_END, SVSM_PERTASK_END_CPL3,
    SVSM_PERTASK_STACK_BASE, SVSM_PERTASK_STACK_BASE_CPL3,
};
use crate::types::PAGE_SHIFT;

use super::schedule::{current_task_terminated, schedule};

extern "C" {
    static task_entry: u64;
}

pub const INITIAL_TASK_ID: u32 = 1;

#[derive(PartialEq, Debug, Copy, Clone, Default)]
pub enum TaskState {
    RUNNING,
    #[default]
    TERMINATED,
}

#[derive(Clone, Copy, Debug)]
pub enum TaskError {
    /// Attempt to close a non-terminated task
    NotTerminated,
    /// A closed task could not be removed from the task list
    CloseFailed,
    /// The task system has not been initialised
    NotInitialised,
    /// Memory allocation error,
    Alloc,
}

impl From<TaskError> for SvsmError {
    fn from(e: TaskError) -> Self {
        Self::Task(e)
    }
}

#[derive(Clone, Copy, Debug)]
struct UserParams {
    entry_point: extern "C" fn(u64),
    param: u64,
}

pub const TASK_FLAG_SHARE_PT: u16 = 0x01;

#[derive(Debug, Default)]
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

    /// Overrides the calculated runtime value with the given value.
    /// This can be used to set or adjust the runtime of a task.
    fn set(&mut self, runtime: u64);

    /// Returns a value that represents the amount of CPU the task
    /// has been allocated
    fn value(&self) -> u64;
}

/// Tracks task runtime based on the CPU timestamp counter
#[derive(Default, Debug)]
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

    fn set(&mut self, runtime: u64) {
        self.runtime = runtime;
    }

    fn value(&self) -> u64 {
        self.runtime
    }
}

/// Tracks task runtime based on the number of times the task has been
/// scheduled
#[derive(Default, Debug, Clone, Copy)]
#[repr(transparent)]
pub struct CountRuntime {
    count: u64,
}

impl TaskRuntime for CountRuntime {
    fn schedule_in(&mut self) {
        self.count += 1;
    }

    fn schedule_out(&mut self) {}

    fn set(&mut self, runtime: u64) {
        self.count = runtime;
    }

    fn value(&self) -> u64 {
        self.count
    }
}

// Define which runtime counter to use
type TaskRuntimeImpl = CountRuntime;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct TaskContext {
    pub rsp: u64,
    pub regs: X86GeneralRegs,
    pub flags: u64,
    pub ret_addr: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct UserTask {
    pub user_rsp: u64,
    pub kernel_rsp: u64,
}

#[repr(C)]
pub struct Task {
    /// Current kernel stack pointer. This must always be the first entry
    /// in this struct
    pub rsp: u64,

    // For tasks that support user mode this contains the current user mode
    // state. For tasks that are kernel mode only, contains None.
    pub user: Option<UserTask>,

    /// Page table that is loaded when the task is scheduled
    pub page_table: SpinLock<PageTableRef>,

    /// Task virtual memory range for use at CPL 0
    vm_kernel_range: VMR,

    /// Task virtual memory range for use at CPL 3
    vm_user_range: VMR,

    /// Current state of the task
    pub state: TaskState,

    /// Task affinity
    /// None: The task can be scheduled to any CPU
    /// u32:  The APIC ID of the CPU that the task must run on
    pub affinity: Option<u32>,

    // APIC ID of the CPU that task has been assigned to. If 'None' then
    // the task is not currently assigned to a CPU
    pub allocation: Option<u32>,

    /// ID of the task
    pub id: u32,

    /// Amount of CPU resource the task has consumed
    pub runtime: TaskRuntimeImpl,

    /// Optional hook that is called immediately after switching to this task
    /// before the context is restored
    pub on_switch_hook: Option<fn(&Self)>,
}

impl fmt::Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task")
            .field("rsp", &self.rsp)
            .field("state", &self.state)
            .field("affinity", &self.affinity)
            .field("id", &self.id)
            .field("runtime", &self.runtime)
            .finish()
    }
}

impl Task {
    pub fn create(
        entry: extern "C" fn(u64),
        param: u64,
        flags: u16,
    ) -> Result<Box<Task>, SvsmError> {
        let mut pgtable = if (flags & TASK_FLAG_SHARE_PT) != 0 {
            this_cpu().get_pgtable().clone_shared()?
        } else {
            Self::allocate_page_table()?
        };

        let mut vm_kernel_range = VMR::new(SVSM_PERTASK_BASE, SVSM_PERTASK_END, PTEntryFlags::USER);
        vm_kernel_range.initialize()?;

        let (stack, rsp_offset) = Self::allocate_stack(entry, param)?;
        vm_kernel_range.insert_at(SVSM_PERTASK_STACK_BASE, stack)?;

        vm_kernel_range.populate(&mut pgtable);

        let mut vm_user_range = VMR::new(
            SVSM_PERTASK_BASE_CPL3,
            SVSM_PERTASK_END_CPL3,
            PTEntryFlags::USER,
        );
        vm_user_range.initialize()?;
        vm_user_range.populate(&mut pgtable);

        let task: Box<Task> = Box::new(Task {
            rsp: (SVSM_PERTASK_STACK_BASE.bits() + rsp_offset.bits()) as u64,
            user: None,
            page_table: SpinLock::new(pgtable),
            vm_kernel_range,
            vm_user_range,
            state: TaskState::RUNNING,
            affinity: None,
            allocation: None,
            id: TASK_ID_ALLOCATOR.next_id(),
            runtime: TaskRuntimeImpl::default(),
            on_switch_hook: None,
        });
        Ok(task)
    }

    pub fn user_create(
        entry: extern "C" fn(u64),
        param: u64,
        flags: u16,
    ) -> Result<Box<Task>, SvsmError> {
        // Launch via the user-mode entry point
        let entry_param = Box::new(UserParams {
            entry_point: entry,
            param,
        });

        let mut task = Self::create(launch_user_entry, Box::into_raw(entry_param) as u64, flags)?;
        task.init_user_mode()?;
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

    pub fn handle_pf(&self, vaddr: VirtAddr, write: bool) -> Result<(), SvsmError> {
        self.vm_kernel_range.handle_page_fault(vaddr, write)
    }

    pub fn vmr_user(&mut self) -> &mut VMR {
        &mut self.vm_user_range
    }

    pub fn virtual_alloc(
        &mut self,
        size_bytes: usize,
        _alignment: usize,
    ) -> Result<VirtAddr, SvsmError> {
        // Each bit in our bitmap represents a 4K page
        if (size_bytes & (PAGE_SIZE - 1)) != 0 {
            return Err(SvsmError::Mem);
        }
        let _page_count = size_bytes >> PAGE_SHIFT;
        // TODO: Implement virtual_alloc
        Err(SvsmError::Mem)
    }

    pub fn virtual_free(&mut self, _vaddr: VirtAddr, _size_bytes: usize) {
        // TODO: Implement virtual_free
    }

    pub fn set_on_switch_hook(&mut self, hook: Option<fn(&Task)>) {
        self.on_switch_hook = hook;
    }

    fn allocate_stack(
        entry: extern "C" fn(u64),
        param: u64,
    ) -> Result<(Arc<Mapping>, VirtAddr), SvsmError> {
        let stack = VMKernelStack::new()?;
        let offset = stack.top_of_stack(VirtAddr::from(0u64));

        let mapping = Arc::new(Mapping::new(stack));
        let percpu_mapping = this_cpu_mut().new_mapping(mapping.clone())?;

        // We need to setup a context on the stack that matches the stack layout
        // defined in switch_context below.
        let stack_ptr: *mut u64 = (percpu_mapping.virt_addr().bits() + offset.bits()) as *mut u64;

        // 'Push' the task frame onto the stack
        unsafe {
            // flags
            stack_ptr.offset(-5).write(read_flags());
            // Task entry point
            stack_ptr.offset(-4).write(&task_entry as *const u64 as u64);
            // Parameter to entry point
            stack_ptr.offset(-3).write(param);
            // ret_addr
            stack_ptr.offset(-2).write(entry as *const () as u64);
            // Task termination handler for when entry point returns
            stack_ptr.offset(-1).write(task_exit as *const () as u64);
        }

        Ok((
            mapping,
            offset - (size_of::<TaskContext>() + 3 * size_of::<u64>()),
        ))
    }

    fn init_user_mode(&mut self) -> Result<(), SvsmError> {
        let stack = VMUserStack::new()?;
        let offset = stack.top_of_stack(VirtAddr::from(0u64));
        let mapping = Arc::new(Mapping::new(stack));
        self.vm_user_range
            .insert_at(SVSM_PERTASK_STACK_BASE_CPL3, mapping)?;

        self.user = Some(UserTask {
            user_rsp: offset.bits() as u64,
            kernel_rsp: 0,
        });
        Ok(())
    }

    fn allocate_page_table() -> Result<PageTableRef, SvsmError> {
        // Base the new task page table on the initial SVSM kernel page table.
        // When the pagetable is schedule to a CPU, the per CPU entry will also
        // be added to the pagetable.
        get_init_pgtable_locked().clone_shared()
    }
}

extern "C" fn launch_user_entry(entry: u64) {
    unsafe {
        let params = *Box::from_raw(entry as *mut UserParams);
        let task_node = this_cpu()
            .runqueue()
            .lock_read()
            .current_task()
            .expect("Task entry point called when not the current task.");
        let (user_rsp, kernel_rsp) = {
            let task = task_node.task.lock_write();
            let user = task
                .user
                .as_ref()
                .expect("User entry point called from kernel task");
            let kernel_rsp = &user.kernel_rsp as *const u64;
            (user.user_rsp, kernel_rsp)
        };

        asm!(
            r#"
                // user mode might change non-volatile registers
                push    %rbx
                push    %rbp
                push    %r12
                push    %r13
                push    %r14
                push    %r15

                // Save the address after the sysretq so when the task
                // exits it can jump there.
                leaq    1f(%rip), %r8
                pushq   %r8

                movq    %rsp, (%rsi)
                movq    %rax, %rsp
                movq    $0x202, %r11
                sysretq

            1:
                pop     %r15
                pop     %r14
                pop     %r13
                pop     %r12
                pop     %rbp
                pop     %rbx
            "#,
            in("rcx") params.entry_point,
            in("rdi") params.param,
            in("rax") user_rsp,
            in("rsi") kernel_rsp,
            options(att_syntax));
    }
}

extern "C" fn task_exit() {
    unsafe {
        current_task_terminated();
    }
    schedule();
}

#[allow(unused)]
#[no_mangle]
extern "C" fn apply_new_context(new_task: *mut Task) -> u64 {
    unsafe {
        let mut pt = (*new_task).page_table.lock();
        this_cpu().populate_page_table(&mut pt);
        pt.cr3_value().bits() as u64
    }
}

#[allow(unused)]
#[no_mangle]
extern "C" fn on_switch(new_task: &mut Task) {
    if let Some(hook) = new_task.on_switch_hook {
        hook(new_task);
    }
}

global_asm!(
    r#"
        .text

    .globl task_entry
    task_entry:
        pop     %rdi        // Parameter to entry point
        // Next item on the stack is the entry point address
        ret         

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
        pushq   %rsp
        
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

        // We've already restored rsp
        addq        $8, %rsp

        mov         %rbx, %rdi
        call        on_switch

        // Restore the task context
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
