// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

//! Round-Robin scheduler implementation for COCONUT-SVSM
//!
//! This module implements a round-robin scheduler for cooperative multi-tasking.
//! It works by assigning a single owner for each struct [`Task`]. The owner
//! depends on the state of the task:
//!
//! * [`RUNNING`] A task in running state is owned by the [`RunQueue`] and either
//!    stored in the `run_list` (when the task is not actively running) or in
//!    `current_task` when it is scheduled on the CPU.
//! * [`BLOCKED`] A task in this state is waiting for an event to become runnable
//!    again. It is owned by a wait object when in this state.
//! * [`TERMINATED`] The task is about to be destroyed and owned by the [`RunQueue`].
//!
//! The scheduler is cooperative. A task runs until it voluntarily calls the
//! [`schedule()`] function.
//!
//! Only when a task is in [`RUNNING`] or [`TERMINATED`] state it is assigned to a
//! specific CPU. Tasks in the [`BLOCKED`] state have no CPU assigned and will run
//! on the CPU where their event is triggered that makes them [`RUNNING`] again.
//!
//! [`RUNNING`]: super::tasks::TaskState::RUNNING
//! [`BLOCKED`]: super::tasks::TaskState::BLOCKED
//! [`TERMINATED`]: super::tasks::TaskState::TERMINATED

extern crate alloc;

use super::INITIAL_TASK_ID;
use super::{Task, TaskListAdapter, TaskPointer, TaskRunListAdapter};
use crate::address::{Address, VirtAddr};
use crate::cpu::ipi::{send_multicast_ipi, IpiMessage, IpiTarget};
use crate::cpu::irq_state::raw_get_tpr;
use crate::cpu::msr::write_msr;
use crate::cpu::percpu::{irq_nesting_count, this_cpu};
use crate::cpu::shadow_stack::{is_cet_ss_supported, IS_CET_SUPPORTED, PL0_SSP};
use crate::cpu::sse::{sse_restore_context, sse_save_context};
use crate::cpu::IrqGuard;
use crate::error::SvsmError;
use crate::fs::Directory;
use crate::locking::SpinLock;
use crate::mm::SVSM_CONTEXT_SWITCH_SHADOW_STACK;
use crate::platform::SVSM_PLATFORM;
use alloc::string::String;
use alloc::sync::Arc;
use core::arch::{asm, global_asm};
use core::cell::OnceCell;
use core::mem::offset_of;
use core::ptr::null_mut;
use intrusive_collections::LinkedList;

/// A RunQueue implementation that uses an RBTree to efficiently sort the priority
/// of tasks within the queue.
#[derive(Debug, Default)]
pub struct RunQueue {
    /// Linked list with runable tasks
    run_list: LinkedList<TaskRunListAdapter>,

    /// Pointer to currently running task
    current_task: Option<TaskPointer>,

    /// Idle task - runs when there is no other runnable task
    idle_task: OnceCell<TaskPointer>,

    /// Temporary storage for tasks which are about to be terminated
    terminated_task: Option<TaskPointer>,

    /// Pointer to a task that should be woken when returning from idle
    wake_from_idle: Option<TaskPointer>,

    /// Pointer to a task that is requesting an affinity change to another
    /// processor, along with the CPU index describing the new affinity..
    set_affinity: Option<(TaskPointer, usize)>,
}

impl RunQueue {
    /// Create a new runqueue for an id. The id would normally be set
    /// to the APIC ID of the CPU that owns the runqueue and is used to
    /// determine the affinity of tasks.
    pub fn new() -> Self {
        Self {
            run_list: LinkedList::new(TaskRunListAdapter::new()),
            current_task: None,
            idle_task: OnceCell::new(),
            terminated_task: None,
            wake_from_idle: None,
            set_affinity: None,
        }
    }

    /// Find the next task to run, which is either the task at the front of the
    /// run_list or the idle task, if the run_list is empty.
    ///
    /// # Returns
    ///
    /// Pointer to next task to run
    ///
    /// # Panics
    ///
    /// Panics if there are no tasks to run and no idle task has been
    /// allocated via [`set_idle_task()`](Self::set_idle_task).
    fn get_next_task(&mut self) -> TaskPointer {
        self.run_list
            .pop_front()
            .unwrap_or_else(|| self.idle_task.get().unwrap().clone())
    }

    /// Update state before a task is scheduled out. Non-idle tasks in RUNNING
    /// state will be put at the end of the run_list. Terminated tasks will be
    /// stored in the terminated_task field of the RunQueue and be destroyed
    /// after the task-switch.
    fn handle_task(&mut self, task: TaskPointer) {
        if task.is_running() && !task.is_idle_task() {
            self.run_list.push_back(task);
        } else if task.is_terminated() {
            self.terminated_task = Some(task);
        }
    }

    /// Initialized the scheduler for this (RunQueue)[RunQueue]. This method is
    /// called on the very first scheduling event when there is no current task
    /// yet.
    ///
    /// # Returns
    ///
    /// [TaskPointer] to the first task to run
    pub fn schedule_init(&mut self) -> TaskPointer {
        let task = self.get_next_task();
        self.current_task = Some(task.clone());
        task
    }

    /// Prepares a task switch. The function checks if a task switch needs to
    /// be done and return pointers to the current and next task. It will
    /// also call `handle_task()` on the current task in case a task-switch
    /// is requested.
    ///
    /// # Returns
    ///
    /// `None` when no task-switch is needed.
    /// `Some` with current and next task in case a task-switch is required.
    ///
    /// # Panics
    ///
    /// Panics if there is no current task.
    pub fn schedule_prepare(&mut self) -> Option<(TaskPointer, TaskPointer)> {
        // Remove current and put it back into the RunQueue in case it is still
        // runnable. This is important to make sure the last runnable task
        // keeps running, even if it calls schedule()
        let current = self.current_task.take().unwrap();
        self.handle_task(current.clone());

        // Get next task and update current_task state
        let next = self.get_next_task();
        self.current_task = Some(next.clone());

        // Check if task switch is needed
        if current != next {
            Some((current, next))
        } else {
            None
        }
    }

    pub fn current_task_id(&self) -> u32 {
        self.current_task
            .as_ref()
            .map_or(INITIAL_TASK_ID, |t| t.get_task_id())
    }

    /// Sets the idle task for this RunQueue. This function sets a
    /// OnceCell at the end and can thus be only called once.
    ///
    /// # Returns
    ///
    /// Ok(()) on success, SvsmError on failure
    ///
    /// # Panics
    ///
    /// Panics if the idle task was already set.
    pub fn set_idle_task(&self, task: TaskPointer) {
        task.set_idle_task();

        // Add idle task to global task list
        TASKLIST.lock().list().push_front(task.clone());

        self.idle_task
            .set(task)
            .expect("Idle task already allocated");
    }

    /// Gets a pointer to the current task
    ///
    /// # Panics
    ///
    /// Panics if there is no current task.
    pub fn current_task(&self) -> TaskPointer {
        self.current_task.as_ref().unwrap().clone()
    }

    /// Wakes a task from idle if required.
    ///
    /// # Returns
    ///
    /// An `Option<TaskPointer>` indicating which task should be woken, if
    /// any.
    pub fn wake_from_idle(&mut self) -> Option<TaskPointer> {
        self.wake_from_idle.take()
    }
}

/// Global task list
/// This contains every task regardless of affinity or run state.
#[derive(Debug, Default)]
pub struct TaskList {
    list: Option<LinkedList<TaskListAdapter>>,
}

impl TaskList {
    pub const fn new() -> Self {
        Self { list: None }
    }

    pub fn list(&mut self) -> &mut LinkedList<TaskListAdapter> {
        self.list
            .get_or_insert_with(|| LinkedList::new(TaskListAdapter::new()))
    }

    pub fn get_task(&self, id: u32) -> Option<TaskPointer> {
        let task_list = &self.list.as_ref()?;
        let mut cursor = task_list.front();
        while let Some(task) = cursor.get() {
            if task.get_task_id() == id {
                return cursor.clone_pointer();
            }
            cursor.move_next();
        }
        None
    }

    fn terminate(&mut self, task: TaskPointer) {
        // Set the task state as terminated. If the task being terminated is the
        // current task then the task context will still need to be in scope until
        // the next schedule() has completed. Schedule will keep a reference to this
        // task until some time after the context switch.
        task.set_task_terminated();
        let mut cursor = unsafe { self.list().cursor_mut_from_ptr(task.as_ref()) };
        cursor.remove();
    }
}

pub static TASKLIST: SpinLock<TaskList> = SpinLock::new(TaskList::new());

/// Creates, initializes and starts a new kernel task. Note that the task has
/// already started to run before this function returns.
///
/// # Arguments
///
/// * entry: The function to run as the new tasks main function
///
/// # Returns
///
/// A new instance of [`TaskPointer`] on success, [`SvsmError`] on failure.
pub fn start_kernel_task(
    entry: extern "C" fn(usize),
    start_parameter: usize,
    name: String,
) -> Result<TaskPointer, SvsmError> {
    let cpu = this_cpu();
    let task = Task::create(cpu, entry, start_parameter, name)?;
    TASKLIST.lock().list().push_back(task.clone());

    // Put task on the runqueue of this CPU
    cpu.runqueue().lock_write().handle_task(task.clone());

    schedule();

    Ok(task)
}

/// Creates and initializes the kernel state of a new user task. The task is
/// not added to the TASKLIST or run-queue yet.
///
/// # Arguments
///
/// * user_entry: The user-space entry point.
///
/// # Returns
///
/// A new instance of [`TaskPointer`] on success, [`SvsmError`] on failure.
pub fn create_user_task(
    user_entry: usize,
    root: Arc<dyn Directory>,
    name: String,
) -> Result<TaskPointer, SvsmError> {
    let cpu = this_cpu();
    Task::create_user(cpu, user_entry, root, name)
}

/// Finished user-space task creation by putting the task on the global
/// TASKLIST and adding it to the run-queue.
///
/// # Arguments
///
/// * task: Pointer to user task
pub fn finish_user_task(task: TaskPointer) {
    // Add task to global TASKLIST
    TASKLIST.lock().list().push_back(task.clone());

    // Put task on the runqueue of this CPU
    this_cpu().runqueue().lock_write().handle_task(task);
}

pub fn current_task() -> TaskPointer {
    this_cpu().current_task()
}

/// Check to see if the task scheduled on the current processor has the given id
pub fn is_current_task(id: u32) -> bool {
    match &this_cpu().runqueue().lock_read().current_task {
        Some(current_task) => current_task.get_task_id() == id,
        None => id == INITIAL_TASK_ID,
    }
}

/// Terminates the current task.
///
/// # Safety
///
/// This function must only be called after scheduling is initialized, otherwise it will panic.
pub unsafe fn current_task_terminated() {
    let cpu = this_cpu();
    let mut rq = cpu.runqueue().lock_write();
    let task_node = rq
        .current_task
        .as_mut()
        .expect("Task termination handler called when there is no current task");
    TASKLIST.lock().terminate(task_node.clone());
}

pub fn terminate() {
    // TODO: re-evaluate whether current_task_terminated() needs to be unsafe
    unsafe {
        current_task_terminated();
    }
    schedule();
}

pub fn go_idle() {
    // Mark this task as blocked and indicate that it is waiting for wake after
    // idle.  Only one task on each CPU can be in the wake-from-idle state at
    // one time.
    let task = this_cpu().current_task();
    task.set_task_blocked();
    let mut runqueue = this_cpu().runqueue().lock_write();
    assert!(runqueue.wake_from_idle.is_none());
    runqueue.wake_from_idle = Some(task);
    drop(runqueue);

    // Find another task to run.  If no other task is runnable, then the idle
    // thread will execute.
    schedule();
}

pub fn set_affinity(cpu_index: usize) {
    // Mark the current task as blocked so it is not scheduled again.
    let task = this_cpu().current_task();
    task.set_task_blocked();

    // Mark this task as the task pending an affinity change.
    let mut runqueue = this_cpu().runqueue().lock_write();
    assert!(runqueue.set_affinity.is_none());
    runqueue.set_affinity = Some((task, cpu_index));
    drop(runqueue);

    // Find another task to run.  The scheduler will complete the affinity
    // change once a new task has been selected on this processor.
    schedule();
}

// SAFETY: This function returns a raw pointer to a task. It is safe
// because this function is only used in the task switch code, which also only
// takes a single reference to the next and previous tasks. Also, this
// function works on an Arc, which ensures that only a single mutable reference
// can exist.
fn task_pointer(taskptr: TaskPointer) -> *const Task {
    Arc::as_ptr(&taskptr)
}

// SAFETY: The caller is required to provide correct pointers for the previous
// and current tasks.
#[inline(always)]
unsafe fn switch_to(prev: *const Task, next: *const Task) {
    // SAFETY: Assuming the caller has provided the correct task pointers,
    // the page table and stack information in those tasks are correct and
    // can be used to switch to the correct page table and execution stack.
    unsafe {
        let cr3 = (*next).page_table.lock().cr3_value().bits() as u64;

        // The location of a cpu-local stack that's mapped into every set of
        // page tables for use during context switches.
        //
        // If an IRQ is raised after switching the page tables but before
        // switching to the new stack, the CPU will try to access the old stack
        // in the new page tables. To protect against this, we switch to another
        // stack that's mapped into both the old and the new set of page tables.
        // That way we always have a valid stack to handle exceptions on.
        let tos_cs: u64 = this_cpu().get_top_of_context_switch_stack().into();

        // Switch to new task
        asm!(
            r#"
            call switch_context
            "#,
            in("r12") prev as u64,
            in("r13") next as u64,
            in("r14") tos_cs,
            in("r15") cr3,
            options(att_syntax));
    }
}

/// Initializes the [RunQueue] on the current CPU. It will switch to the idle
/// task and initialize the current_task field of the RunQueue. After this
/// function has ran it is safe to call [`schedule()`] on the current CPU.
///
/// # Safety
///
/// This function can only be called when it is known that there is no current
/// task.  Otherwise, the run state can become corrupted, and thus future
/// calculation of task pointers can be incorrect.
pub unsafe fn schedule_init() {
    let guard = IrqGuard::new();
    // SAFETY: The caller guarantees that there is no current task, and the
    // pointer obtained for the next task will always be correct, thus
    // providing a guarantee that the task switch will be safe.
    unsafe {
        let next = task_pointer(this_cpu().schedule_init());
        switch_to(null_mut(), next);
    }
    drop(guard);
}

fn preemption_checks() {
    assert!(irq_nesting_count() == 0);
    assert!(raw_get_tpr() == 0 || !SVSM_PLATFORM.use_interrupts());
}

/// Perform a task switch and hand the CPU over to the next task on the
/// run-list. In case the current task is terminated, it will be destroyed after
/// the switch to the next task.
pub fn schedule() {
    // check if preemption is safe
    preemption_checks();

    let guard = IrqGuard::new();

    let work = this_cpu().schedule_prepare();

    // !!! Runqueue lock must be release here !!!
    if let Some((current, next)) = work {
        // Update per-cpu mappings if needed
        let cpu_index = this_cpu().get_cpu_index();

        if next.update_cpu(cpu_index) != cpu_index {
            // Task has changed CPU, update per-cpu mappings
            let mut pt = next.page_table.lock();
            this_cpu().populate_page_table(&mut pt);
        }

        // SAFETY: ths stack pointer is known to be correct.
        unsafe {
            this_cpu().set_tss_rsp0(next.stack_bounds.end());
        }
        if is_cet_ss_supported() {
            // SAFETY: Task::exception_shadow_stack is always initialized when
            // creating a new Task.
            unsafe {
                write_msr(PL0_SSP, next.exception_shadow_stack.bits() as u64);
            }
        }

        // Get task-pointers, consuming the Arcs and release their reference
        unsafe {
            let a = task_pointer(current);
            let b = task_pointer(next);
            sse_save_context(u64::from((*a).xsa.vaddr()));

            // Switch tasks
            switch_to(a, b);

            // We're now in the context of task pointed to by 'a'
            // which was previously scheduled out.
            sse_restore_context(u64::from((*a).xsa.vaddr()));
        }
    }

    drop(guard);

    // Perform housekeeping actions following a task switch.
    after_task_switch();

    // If the previous task had terminated then we can release
    // it's reference here.
    let _ = this_cpu().runqueue().lock_write().terminated_task.take();
}

struct SetAffinityMessage {
    task: TaskPointer,
}

// SAFETY: The SetAffinityMessage structure contains no references other than
// global references, and can safely rely on the default implementation of the
// IPI message copy routines.
unsafe impl IpiMessage for SetAffinityMessage {
    fn invoke(&self) {
        // Mark the task as runnable on the current CPU.  It will be selected
        // to run at the next scheduling interval.  If the CPU is currently
        // idle, then the idle task will wake and invoke the scheduler to
        // invoke this task.
        assert!(!self.task.is_running());
        enqueue_task(self.task.clone());
    }
}

pub fn after_task_switch() {
    // Determine whether any task is pending an affinity change.  This must be
    // done with the run queue locked, but the actual affinity change must
    // happen without holding the run queue lock.
    let mut runqueue = this_cpu().runqueue().lock_write();
    let set_affinity = runqueue.set_affinity.take();
    drop(runqueue);

    if let Some((task, cpu_index)) = set_affinity {
        // Send an IPI to the target processor indicating which task it should
        // take.
        let set_affinity_message = SetAffinityMessage { task };
        send_multicast_ipi(IpiTarget::Single(cpu_index), &set_affinity_message);
    }
}

fn enqueue_task(task: TaskPointer) {
    task.set_task_running();
    this_cpu().runqueue().lock_write().handle_task(task);
}

pub fn schedule_task(task: TaskPointer) {
    enqueue_task(task);
    schedule();
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
        pushq   %rsp

        // If `prev` is not null...
        testq   %r12, %r12
        // The initial stack is always mapped in the new page table.
        jz      1f

        // Save the current stack pointer
        movq    %rsp, {TASK_RSP_OFFSET}(%r12)

        // Switch to a stack pointer that's valid in both the old and new page tables.
        mov     %r14, %rsp

        cmpb    $0, {IS_CET_SUPPORTED}(%rip)
        je      1f
        // Save the current shadow stack pointer
        rdssp   %rax
        sub     $8, %rax
        movq    %rax, {TASK_SSP_OFFSET}(%r12)
        // Switch to a shadow stack that's valid in both page tables and move
        // the "shadow stack restore token" to the old shadow stack.
        mov     ${CONTEXT_SWITCH_RESTORE_TOKEN}, %rax
        rstorssp (%rax)
        saveprevssp

    1:
        // Switch to the new task state

        // Switch to the new task page tables
        mov     %r15, %cr3

        cmpb    $0, {IS_CET_SUPPORTED}(%rip)
        je      2f
        // Switch to the new task shadow stack and move the "shadow stack
        // restore token" back.
        mov     {TASK_SSP_OFFSET}(%r13), %rdx
        rstorssp (%rdx)
        saveprevssp
    2:

        // Switch to the new task stack
        movq    {TASK_RSP_OFFSET}(%r13), %rsp

        // We've already restored rsp
        addq    $8, %rsp

        // Restore the task context
        popq    %r15
        popq    %r14
        popq    %r13
        popq    %r12
        popq    %r11
        popq    %r10
        popq    %r9
        popq    %r8
        popq    %rbp
        popq    %rdi
        popq    %rsi
        popq    %rdx
        popq    %rcx
        popq    %rbx
        popq    %rax
        popfq

        ret
    "#,
    TASK_RSP_OFFSET = const offset_of!(Task, rsp),
    TASK_SSP_OFFSET = const offset_of!(Task, ssp),
    IS_CET_SUPPORTED = sym IS_CET_SUPPORTED,
    CONTEXT_SWITCH_RESTORE_TOKEN = const CONTEXT_SWITCH_RESTORE_TOKEN.as_usize(),
    options(att_syntax)
);

/// The location of a cpu-local shadow stack restore token that's mapped into
/// every set of page tables for use during context switches.
///
/// One interesting difference between the normal stack pointer and the shadow
/// stack pointer is how they can be switched: For the normal stack pointer we
/// can just move a new value into the RSP register. This doesn't work for the
/// SSP register (the shadow stack pointer) because there's no way to directly
/// move a value into it. Instead we have to use the `rstorssp` instruction.
/// The key difference between this instruction and a regular `mov` is that
/// `rstorssp` expects a "shadow stack restore token" to be at the top of the
/// new shadow stack (this is just a special value that marks the top of a
/// inactive shadow stack). After switching to a new shadow stack, the previous
/// shadow stack is now inactive, and so the `saveprevssp` instruction can be
/// used to transfer the shadow stack restore token from the new shadow stack
/// to the previous one: `saveprevssp` atomically pops the stack token of the
/// new shadow stack and pushes it on the previous shadow stack. This means
/// that we have to execute both `rstorssp` and `saveprevssp` every time we
/// want to switch the shadow stacks.
///
/// There's one major problem though: `saveprevssp` needs to access both the
/// previous and the new shadow stack, but we only map each shadow stack into a
/// single task's page tables. If each set of page tables only has access to
/// either the previous or the new shadow stack, but not both, we can't execute
/// `saveprevssp` and so we we can't move the shadow stack restore token to the
/// previous shadow stack. If there's no shadow stack restore token on the
/// previous shadow stack that means we can't restore this shadow stack at a
/// later point. To work around this, we map another shadow stack into each
/// CPU's set of pagetables. This allows us to do the following:
///
/// 1. Switch to the context-switch shadow stack using `rstorssp`.
/// 2. Transfer the shadow stack restore token from the context switch shadow
///    stack to the previous shadow stack by executing `saveprevssp`.
/// 3. Switch the page tables. This doesn't lead to problems with the context
///    switch shadow stack because it's mapped into both page tables.
/// 4. Switch to the new shadow stack using `rstorssp`.
/// 5. Transfer the shadow stack restore token from the new shadow stack back
///    to the context switch shadow stacks by executing `saveprevssp`.
///
/// We just switched between two shadow stack tables in different page tables :)
const CONTEXT_SWITCH_RESTORE_TOKEN: VirtAddr = SVSM_CONTEXT_SWITCH_SHADOW_STACK.const_add(0xff8);
