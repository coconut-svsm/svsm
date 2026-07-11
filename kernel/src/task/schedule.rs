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
//! * [`PENDING`] A task has been created but has not yet been scheduled for
//!   the first time, nor has it been placed into any wait queue or any other
//!   type of queue.
//! * [`RUNNING`] A task in running state is owned by the [`RunQueue`] and either
//!   stored in the `run_list` (when the task is not actively running) or in
//!   `current_task` when it is scheduled on the CPU.
//! * [`BLOCKED`] A task in this state is waiting for an event to become runnable
//!   again. It is owned by a wait object when in this state.
//! * [`TERMINATED`] The task is about to be destroyed and owned by the [`RunQueue`].
//!
//! The scheduler is cooperative. A task runs until it voluntarily calls the
//! [`schedule()`] function.
//!
//! Only when a task is in [`RUNNING`] or [`TERMINATED`] state it is assigned to a
//! specific CPU. Tasks in the [`BLOCKED`] state have no CPU assigned and will run
//! on the CPU where their event is triggered that makes them [`RUNNING`] again.
//!
//! [`PENDING`]: super::tasks::TaskState::PENDING
//! [`RUNNING`]: super::tasks::TaskState::RUNNING
//! [`BLOCKED`]: super::tasks::TaskState::BLOCKED
//! [`TERMINATED`]: super::tasks::TaskState::TERMINATED

extern crate alloc;

use super::tasks::TASK_ACTIVE_OFFSET;
use super::tasks::TASK_CUR_CPU_OFFSET;
use super::tasks::TaskExitStatus;
use super::{
    INITIAL_TASK_ID, KernelThreadStartInfo, Task, TaskListAdapter, TaskPointer, TaskRunListAdapter,
    UserExecInfo,
};
use crate::address::{Address, VirtAddr};
use crate::cpu::IrqGuard;
use crate::cpu::idt::common::SCHEDULE_VECTOR;
use crate::cpu::irq_state::raw_get_tpr;
use crate::cpu::msr::write_msr;
use crate::cpu::percpu::PERCPU_AREAS;
use crate::cpu::percpu::PERCPU_CTXT_SWITCH_STACK_OFFSET;
use crate::cpu::percpu::PERCPU_PAGING_ROOT_OFFSET;
use crate::cpu::percpu::PERCPU_SHARED_INDEX_OFFSET;
use crate::cpu::percpu::PERCPU_SHARED_OFFSET;
use crate::cpu::percpu::irq_nesting_count;
use crate::cpu::percpu::this_cpu;
use crate::cpu::shadow_stack::{IS_CET_ENABLED, PL0_SSP, is_cet_ss_enabled};
use crate::cpu::sse::{sse_restore_context, sse_save_context};
use crate::cpu::x86::apic_post_irq;
use crate::error::SvsmError;
use crate::fs::Directory;
use crate::locking::SpinLock;
use crate::mm::SVSM_CONTEXT_SWITCH_SHADOW_STACK;
use crate::platform::SVSM_PLATFORM;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::arch::global_asm;
use core::mem::offset_of;
use core::ptr;
use core::ptr::null_mut;
use cpuarch::x86apic::ApicIcr;
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
    idle_task: Option<TaskPointer>,

    /// Pointer to a task that should be woken when returning from idle
    wake_from_idle: Option<TaskPointer>,
}

impl RunQueue {
    /// Create a new runqueue for an id. The id would normally be set
    /// to the APIC ID of the CPU that owns the runqueue and is used to
    /// determine the affinity of tasks.
    pub fn new() -> Self {
        Self {
            run_list: LinkedList::new(TaskRunListAdapter::new()),
            current_task: None,
            idle_task: None,
            wake_from_idle: None,
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
            .unwrap_or_else(|| self.idle_task.clone().unwrap())
    }

    /// Place a task back onto the run queue so it can be scheduled again.
    fn enqueue_task(&mut self, task: TaskPointer) {
        // Callers are expected to place the task into the RUNNING state
        // before a task is queued.
        debug_assert!(task.is_running());
        if !task.is_idle_task() {
            self.run_list.push_back(task);
        }
    }

    /// Prepare to run a task by marking it runnable and placing it into the
    /// run queue.
    fn prepare_run_task(&mut self, task: TaskPointer) {
        task.set_task_running();
        self.enqueue_task(task);
    }

    /// Initializes the scheduler for this (RunQueue)[RunQueue]. This method is
    /// called on the very first scheduling event when there is no current task
    /// yet.  For consistency, it will always invoke the idle task using an
    /// abbreviated task switch flow, and if there is another task that can
    /// run, a full task switch will then occur.
    ///
    /// # Returns
    ///
    /// [TaskPointer] to the first task to run
    pub fn schedule_init(&mut self) -> TaskPointer {
        let task = self.idle_task.as_ref().unwrap().clone();
        self.current_task = Some(task.clone());
        task
    }

    /// Prepares a task switch. The function checks if a task switch needs to
    /// be done and return pointers to the current and next task. It will
    /// also call `enqueue_task()` on the current task in case a task-switch
    /// is requested.
    ///
    /// # Parameters
    ///
    /// - `reschedule`: Indicates whether the current task being rescheduled.
    ///   If so, it will be reinserted on the run list of the current
    ///   processor.
    ///
    /// # Returns
    ///
    /// `None` when no task-switch is needed.
    /// `Some` with current and next task in case a task-switch is required.
    ///
    /// # Panics
    ///
    /// Panics if there is no current task.
    pub fn schedule_prepare(&mut self, reschedule: bool) -> Option<(TaskPointer, TaskPointer)> {
        let current = if reschedule {
            // Remove current and put it back into the RunQueue.  This is
            // important to make sure the last runnable task keeps running,
            // even if it calls schedule()
            let current = self.current_task.take().unwrap();
            self.enqueue_task(current.clone());
            current
        } else {
            self.current_task.as_ref().unwrap().clone()
        };

        // Get next task and update current_task state
        let next = self.get_next_task();
        self.current_task = Some(next.clone());

        // Check if task switch is needed
        if current != next {
            Some((current, next))
        } else {
            // A task switch is expected unless the current task is being
            // rescheduled.
            debug_assert!(reschedule);
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
    pub fn set_idle_task(&mut self, task: TaskPointer) {
        task.set_idle_task();
        task.set_task_running();

        // Add idle task to global task list
        TASKLIST.lock().list().push_front(task.clone());

        self.idle_task.replace(task);
    }

    /// Gets a pointer to the idle task
    ///
    /// # Panics
    ///
    /// Panics if the idle task has not yet been set.
    pub fn get_idle_task(&self) -> TaskPointer {
        self.idle_task.as_ref().unwrap().clone()
    }

    /// Gets a pointer to the current task
    ///
    /// returns idle task if there is no current task.
    pub fn current_task(&self) -> TaskPointer {
        self.current_task
            .as_ref()
            .map_or(self.idle_task.as_ref().unwrap().clone(), |t| t.clone())
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

    /// # Safety
    /// The caller must ensure that `task` is already a member of this task
    /// list.
    unsafe fn terminate(&mut self, task: TaskPointer) -> Option<TaskPointer> {
        // Set the task state as terminated. If the task being terminated is the
        // current task then the task context will still need to be in scope until
        // the next schedule() has completed. Schedule will keep a reference to this
        // task until some time after the context switch.
        let wakeup = task.set_task_terminated();
        // SAFETY: `task` must be a task pointer that is part of this list.
        let mut cursor = unsafe { self.list().cursor_mut_from_ptr(task.as_ref()) };
        cursor.remove();

        // Inform the caller about any task that may need to be woken.
        wakeup
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
    start_info: KernelThreadStartInfo,
    name: String,
) -> Result<TaskPointer, SvsmError> {
    let cpu = this_cpu();
    let task = Task::create(cpu, start_info, name)?;
    TASKLIST.lock().list().push_back(task.clone());

    // Put task on the runqueue of this CPU
    cpu.runqueue_mut().prepare_run_task(task.clone());

    schedule();

    Ok(task)
}

/// Creates, initializes and starts a new kernel thread of the currently
/// running kernel task. Note that the thread has already started to run before
/// this function returns.
///
/// # Arguments
///
/// * `entry` -  The function to run as the new task's main function
/// * `start_parameter` - Parameter of type `usize` to pass to the new threads main function.
///
/// # Returns
///
/// A new instance of [`TaskPointer`] on success, [`SvsmError`] on failure.
pub fn start_kernel_thread(start_info: KernelThreadStartInfo) -> Result<TaskPointer, SvsmError> {
    let current_task = current_task();
    let cpu = this_cpu();
    let task = Task::create_thread(
        cpu,
        start_info,
        current_task.get_task_name().clone(),
        current_task,
    )?;
    TASKLIST.lock().list().push_back(task.clone());

    // Put task on the runqueue of this CPU
    cpu.runqueue_mut().prepare_run_task(task.clone());

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
    info: Box<UserExecInfo>,
    root: Arc<dyn Directory>,
    name: String,
) -> Result<TaskPointer, SvsmError> {
    let cpu = this_cpu();
    Task::create_user(cpu, info, root, name)
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
    this_cpu().runqueue_mut().prepare_run_task(task);
}

pub fn current_task() -> TaskPointer {
    this_cpu().current_task()
}

/// Check to see if the task scheduled on the current processor has the given id
pub fn is_current_task(id: u32) -> bool {
    match &this_cpu().runqueue().current_task {
        Some(current_task) => current_task.get_task_id() == id,
        None => id == INITIAL_TASK_ID,
    }
}

/// Waits for a task to terminate
pub fn wait_for_termination(task: TaskPointer) {
    // Waiting may require a task switch, so ensure that this is safe.
    preemption_checks();

    // Prepare a wait state based on the current execution state of the target
    // task.
    let wait_result = task.wait_for_exit();

    // If a wait is required, then switch to a different task until the wait
    // can be satisfied.
    if let Some(guard) = wait_result {
        select_new_task(false, Some(guard));
    }
}

/// Terminates the current task.
///
/// # Panic
///
/// This function must only be called after scheduling is initialized, otherwise it will panic.
fn current_task_terminated() {
    let cpu = this_cpu();
    let mut rq = cpu.runqueue_mut();

    let task_node = rq
        .current_task
        .as_mut()
        .expect("Task termination handler called when there is no current task");
    // SAFETY: the scheduler guarantees that `current_task` always points to a
    // valid task, and every task has its pointer pushed into the global task
    // list during its creation.
    let wakeup = unsafe { TASKLIST.lock().terminate(task_node.clone()) };

    // If another thread must be woken as a result of the termination, then
    // schedule it now.
    if let Some(wake_task) = wakeup {
        rq.prepare_run_task(wake_task);
    }
}

/// Terminate the current task and optionally set its exit status.
/// If no exit status is provided, then the task will terminate
/// with the default value `Exited(0)`.
pub fn terminate(exit_status: Option<TaskExitStatus>) -> ! {
    // Terminating a task will result in a task change, so preemption must
    // be allowable.
    preemption_checks();

    if let Some(status) = exit_status {
        current_task().set_exit_status(status);
    }

    current_task_terminated();

    // The current task will not run again, so switch to a different task.
    select_new_task(false, None);
    unreachable!("terminated task rescheduled");
}

pub fn go_idle() {
    // Entering an idle state will result in a task change, so preemption must
    // be allowable.
    preemption_checks();

    // Mark this task as blocked and indicate that it is waiting for wake after
    // idle.  Only one task on each CPU can be in the wake-from-idle state at
    // one time.
    let task = this_cpu().current_task();
    task.set_task_blocked();
    let mut runqueue = this_cpu().runqueue_mut();
    assert!(runqueue.wake_from_idle.is_none());
    runqueue.wake_from_idle = Some(task);
    drop(runqueue);

    // Find another task to run.  If no other task is runnable, then the idle
    // thread will execute.
    select_new_task(false, None);
}

pub fn set_affinity(cpu_index: usize) {
    // Changes to affinity mak cause a scheduling change, so verify that
    // scheduling operations are safe.
    preemption_checks();

    // Affinity signaling is only required if the target CPU is not the current
    // CPU.
    if cpu_index != this_cpu().get_cpu_index() {
        let task = this_cpu().current_task();
        let target_cpu = PERCPU_AREAS.get_by_cpu_index(cpu_index);

        // Disable interrupts to prevent delays in scheduling once the task
        // has been queued on the target processor.
        let guard = IrqGuard::new();

        // Join this task to the run queue of the target CPU.
        target_cpu.runqueue_mut().enqueue_task(task);

        // Send a scheduler interrupt to the target CPU so that if it is idle,
        // it wakes and runs this task.
        let icr = ApicIcr::new()
            .with_vector(SCHEDULE_VECTOR as u8)
            .with_destination(target_cpu.apic_id());
        apic_post_irq(icr.into());

        // Find another task to run.  The scheduler will complete the affinity
        // change once a new task has been selected on this processor.
        select_new_task(false, Some(guard));
    }
}

// SAFETY: the caller is required to guarantee that the incoming task is
// referenced somewhere (at least the current CPU's run queue current task
// pointer) or else it will be destroyed before it is entered.
#[inline(always)]
unsafe fn switch_to(prev_task: Option<TaskPointer>, next_task: TaskPointer) -> Option<TaskPointer> {
    // Capture a pointer to the new task and consume its `Arc`.  The caller
    // guarantees that the task will still exist.
    let next = Arc::as_ptr(&next_task);
    drop(next_task);

    // Consume the `Arc` describing the currently executing task without
    // adjusting the reference count.  This will ensure that the current task
    // is not fully dereferenced while it is still executing.  The reference
    // will be rebalanced after the task switch.
    let prev = if let Some(task) = prev_task {
        Arc::into_raw(task)
    } else {
        null_mut()
    };

    // SAFETY: Assuming the caller has provided the correct task pointers,
    // the page table and stack information in those tasks are correct and
    // can be used to switch to the correct page table and execution stack.
    unsafe {
        let cr3 = (*next).page_table.lock().cr3_value().bits();

        // Switch to new task
        let new_prev = switch_context(
            prev as usize,
            next as usize,
            ptr::from_ref(this_cpu()) as usize,
            cr3,
        );
        complete_task_switch(new_prev)
    }
}

/// # Safety
/// The caller must guarantee that the task pointer argument is the one that
/// was returned from the context switcher.
pub unsafe fn complete_task_switch(prev: usize) -> Option<TaskPointer> {
    // If there was a previous task, then create a new `Arc` that describes
    // the previous task.  This will balance the reference count that was
    // not decremented when the `Arc` was consumed prior to the task
    // switch.
    if prev != 0 {
        // SAFETY: the caller guarantees that the task pointer is valid.
        unsafe { Some(Arc::from_raw(prev as *const Task)) }
    } else {
        None
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
    let prev_task = unsafe { switch_to(None, this_cpu().schedule_init()) };

    // Drop the interrupt guard before allowing the previous task reference to
    // go out of scope.  This ensures that the task destructor will run with
    // interrupts enabled.
    drop(guard);
    drop(prev_task);
}

/// Enters an idle state if there is no task that can run.
pub fn scheduler_idle() {
    // All decisions must be made with interrupts disabled to ensure that the
    // scheduler state does not change before committing to go idle.
    let guard = IrqGuard::new();

    let queue_empty = this_cpu().runqueue_mut().run_list.front().is_null();

    if queue_empty {
        SVSM_PLATFORM.idle_halt(&guard);
    }
}

fn preemption_checks() {
    assert!(irq_nesting_count() == 0);
    assert!(raw_get_tpr() == 0);
}

/// # Safety
/// The caller must guarantee that this is only called on a valid task pointer
/// that is actively scheduled on the current CPU.  Called only from the
/// task switch code.
#[unsafe(no_mangle)]
pub unsafe fn update_task_percpu_page_tables(t: *const Task) {
    // SAFETY: the caller guarantees the correctness of the task pointer.
    let task = unsafe { &*t };
    let mut pt = task.page_table.lock();
    this_cpu().populate_page_table(&mut pt);
}

/// Perform a task switch and hand the CPU over to the next task on the
/// run-list. In case the current task is terminated, it will be destroyed after
/// the switch to the next task.
pub fn schedule() {
    // check if preemption is safe
    preemption_checks();

    select_new_task(true, None);
}

/// Select another task to run.  If rescheduling is requested, the current
/// task will be placed back on the current processor's run queue so it can
/// be eligible to run again.
fn select_new_task(reschedule: bool, irq_guard: Option<IrqGuard>) {
    // If the caller has not already disabled interrupts, then disable them
    // now.
    let guard = irq_guard.unwrap_or_default();

    let work = this_cpu().schedule_prepare(reschedule);

    // !!! Runqueue lock must be released here !!!
    let prev_task = if let Some((current, next)) = work {
        // Ensure that the current stack bounds of the current CPU are adjusted
        // to reflect the task being scheduled.
        this_cpu().set_current_stack(next.stack_bounds());

        // SAFETY: ths stack pointer is known to be correct.
        unsafe {
            this_cpu().set_tss_rsp0(next.stack_bounds.end());
        }
        if is_cet_ss_enabled() {
            // SAFETY: Task::exception_shadow_stack is always initialized when
            // creating a new Task.
            unsafe {
                write_msr(PL0_SSP, next.shadow_stack_base.bits() as u64);
            }
        }

        // Get task-pointers.
        //
        // SAFETY: the scheduler guarantees that both `current` and `next`
        // always point to valid tasks. The XSAVE area in each task must be
        // valid and not aliased.
        unsafe {
            // Capture a pointer to the current task.  This pointer can be
            // decoupled from the lifetime of the `Arc` because it is valid
            // as long as the task continues to execute.
            let current_ptr = Arc::as_ptr(&current);
            sse_save_context(u64::from((*current_ptr).xsa.vaddr()));

            // Switch tasks.  This call must consume the `Arc` references to
            // both tasks because this call might never return (if the current
            // task is being terminated) and therefore no references can live
            // beyond this call.  This call will return an `Arc` reference to
            // the task that ran most recently, which may be the final
            // reference to the task if the task was terminated.
            let prev_task = switch_to(Some(current), next);

            // The previously captured task pointer is known to be valid
            // because the task is still executing.
            sse_restore_context(u64::from((*current_ptr).xsa.vaddr()));

            prev_task
        }
    } else {
        None
    };

    // Drop the interrupt guard before allowing the previous task reference to
    // go out of scope.  This ensures that the task destructor will run with
    // interrupts enabled.
    drop(guard);
    drop(prev_task);
}

pub fn wake_and_schedule_task(task: TaskPointer) {
    debug_assert!(!task.is_running());
    this_cpu().runqueue_mut().prepare_run_task(task);
    schedule();
}

unsafe extern "C" {
    fn switch_context(prev: usize, next: usize, this_cpu: usize, cr3: usize) -> usize;
}

global_asm!(
    r#"
        .section .text

    switch_context:
        // Arguments:
        // rdi: previous task pointer
        // rsi: new task pointer
        // rdx: current per-CPU pointer
        // rcx: paging root of the new task
        //
        // Save the current context. The layout must match the TaskContext
        // structure.  Only callee-save registers need to be pushed here; the
        // remainder of the TaskContext frame can simply be allocated on the
        // stack.
        pushq   %rbp
        pushq   %rbx
        pushq   %r15
        pushq   %r14
        pushq   %r13
        pushq   %r12
        subq    $24, %rsp

        // If `prev` is not null...
        testq   %rdi, %rdi
        // The initial stack is always mapped in the new page table.
        jz      1f

        // Save the current stack pointer
        movq    %rsp, {TASK_RSP_OFFSET}(%rdi)

        // Switch to a stack pointer that's valid in both the old and new page
        // tables.
        mov     {CONTEXT_SWITCH_RSP_OFFSET}(%rdx), %rsp

        // Clear the frame pointer since it is no longer meaningful.
        xorl    %ebp, %ebp

        // Switch shadow stacks if required.
        cmpb    $0, {IS_CET_ENABLED}(%rip)
        je      4f
        // Save the current shadow stack pointer
        rdssp   %rax
        sub     $8, %rax
        movq    %rax, {TASK_SSP_OFFSET}(%rdi)
        // Switch to a shadow stack that's valid in both page tables and move
        // the "shadow stack restore token" to the old shadow stack.
        mov     ${CONTEXT_SWITCH_RESTORE_TOKEN}, %rax
        rstorssp (%rax)
        saveprevssp

    4:
        // Switch to the current CPU's page table to ensure that the page
        // table remains correct for the current CPU even if the previous task
        // is scheduled onto another CPU and has its per-CPU address space
        // updated.
        movq    {PERCPU_PGTBL_OFFSET}(%rdx), %rax
        movq    %rax, %cr3

        // Mark the previous task as inactive.  This must be done after
        // switching off of its stack because as soon as it is marked as
        // inactive, another processor is free to immediately switch to that
        // thread's stack.
        andb    $0, {TASK_STATE_ACTIVE}(%rdi)

    1:
        // Switch to the new task state.

        // Wait until the new task is inactive.  It may still be running
        // on another processor so its stack cannot be consumed until its
        // stack is no longer active on any processor.
    3:
        pause
        movb    $1, %al
        lock xchgb {TASK_STATE_ACTIVE}(%rsi), %al
        testb   %al, %al
        jnz     3b

        // Check to see whether the task is moving across CPUs.  If so, its
        // per-CPU page table state must be updated.
        movq    {PERCPU_SHARED_OFFSET}(%rdx), %r8
        movq    {PERCPU_SHARED_INDEX_OFFSET}(%r8), %rax
        cmpq    {TASK_CPU_OFFSET}(%rsi), %rax
        jz      5f
        movq    %rax, {TASK_CPU_OFFSET}(%rsi)

        // Save local registers before calling out to do the page table update.
        // Save only the registers that will be needed following the update,
        // and ensure that a multiple of 16 bytes is pushed to maintain
        // compliance with the stack ABI requirement.
        pushq   %rsi
        pushq   %rdi
        pushq   %rcx
        subq    $8, %rsp

        movq    %rsi, %rdi
        call    update_task_percpu_page_tables

        addq    $8, %rsp
        popq    %rcx
        popq    %rdi
        popq    %rsi

    5:
        // Switch to the new task page tables
        movq    %rcx, %cr3

        cmpb    $0, {IS_CET_ENABLED}(%rip)
        je      2f
        // Switch to the new task shadow stack and move the "shadow stack
        // restore token" back.
        mov     {TASK_SSP_OFFSET}(%rsi), %rax
        rstorssp (%rax)
        saveprevssp

    2:
        // Switch to the new task stack
        movq    {TASK_RSP_OFFSET}(%rsi), %rsp

        // Pass the previous task pointer (if any) back to the caller.  This
        // is done both as a return value (if this function was called from
        // the task switcher) and as the first parameter (if this routine
        // will return to the task entry point.
        movq    %rdi, %rax

        // Restore the task state, following the layout of TaskContext.
        popq    %rsi
        popq    %rdx
        popq    %rcx
        popq    %r12
        popq    %r13
        popq    %r14
        popq    %r15
        popq    %rbx
        popq    %rbp

        ret
    "#,
    TASK_RSP_OFFSET = const offset_of!(Task, rsp),
    TASK_SSP_OFFSET = const offset_of!(Task, ssp),
    TASK_STATE_ACTIVE = const TASK_ACTIVE_OFFSET,
    TASK_CPU_OFFSET = const TASK_CUR_CPU_OFFSET,
    IS_CET_ENABLED = sym IS_CET_ENABLED,
    CONTEXT_SWITCH_RSP_OFFSET = const PERCPU_CTXT_SWITCH_STACK_OFFSET,
    PERCPU_SHARED_OFFSET = const PERCPU_SHARED_OFFSET,
    PERCPU_SHARED_INDEX_OFFSET = const PERCPU_SHARED_INDEX_OFFSET,
    PERCPU_PGTBL_OFFSET = const PERCPU_PAGING_ROOT_OFFSET,
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
///
/// Stack offset calculation:
///
/// 0x1ff8 = Size(GuardPage) + Size(ShadowStack) - 8; where Size(GuardPage) == Size(ShadowStack) == PAGE_SIZE.
const CONTEXT_SWITCH_RESTORE_TOKEN: VirtAddr = SVSM_CONTEXT_SWITCH_SHADOW_STACK.const_add(0x1ff8);

#[cfg(all(test, test_in_svsm))]
mod test {
    extern crate alloc;
    use super::KernelThreadStartInfo;
    use super::set_affinity;
    use super::start_kernel_task;
    use super::wait_for_termination;
    use crate::cpu::percpu::{PERCPU_AREAS, this_cpu};
    use alloc::string::String;
    use core::sync::atomic::AtomicU32;
    use core::sync::atomic::Ordering;

    static EMPTY_TASK_COUNTER: AtomicU32 = AtomicU32::new(0);

    fn empty_task(parameter: usize) {
        // Move to a different processor if the caller requested it.
        if parameter != 0 {
            let target_cpu = PERCPU_AREAS.len() - 1;
            set_affinity(target_cpu);
        }

        EMPTY_TASK_COUNTER.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_task_termination() {
        // Start a task that will immediately terminate.
        start_kernel_task(
            KernelThreadStartInfo::new(empty_task, 0),
            String::from("test termination task"),
        )
        .expect("Failed to start test termination task");
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_wait_for_termination() {
        // Reset the task execution counter.
        EMPTY_TASK_COUNTER.store(0, Ordering::Relaxed);

        // Start a task that will move to a remote processor (if available)
        // and will then terminate.
        let task = start_kernel_task(
            KernelThreadStartInfo::new(empty_task, 1),
            String::from("test termination task"),
        )
        .expect("Failed to start test termination task");

        // Wait for that task to terminate.  This might or might not involve
        // waiting, depending on how quickly the new task migrates to another
        // processor.
        wait_for_termination(task.clone());

        // Verify that the task ran.
        assert_eq!(EMPTY_TASK_COUNTER.load(Ordering::Relaxed), 1);

        // Wait again for the task to terminate.  This should return
        // immediately.
        wait_for_termination(task);
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_set_affinity() {
        let cpu_index = this_cpu().get_cpu_index();

        // First test the case of moving the current thread to the current
        // CPU.
        set_affinity(cpu_index);
        assert_eq!(this_cpu().get_cpu_index(), cpu_index);

        // Move this thread to every other CPU in the system.
        let cpu_count = PERCPU_AREAS.len();
        for index in 0..cpu_count {
            if index != cpu_index {
                set_affinity(index);
                assert_eq!(this_cpu().get_cpu_index(), index);
            }
        }

        // Move this thread back to its starting point.
        set_affinity(cpu_index);
    }
}
