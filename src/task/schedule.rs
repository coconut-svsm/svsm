// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use core::ptr::null_mut;

use super::INITIAL_TASK_ID;
use super::{Task, TASK_FLAG_SHARE_PT};
use crate::cpu::percpu::{this_cpu, this_cpu_mut};
use crate::error::SvsmError;
use crate::locking::{RWLock, SpinLock};
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::arch::{asm, global_asm};
use core::cell::OnceCell;
use intrusive_collections::{intrusive_adapter, LinkedList, LinkedListAtomicLink};

/// Round-Robin scheduler implementation for COCONUT-SVSM
///
/// This file implements a round-robin scheduler for cooperative multi-tasking.
/// It works by assigning a single owner for each struct [Task]. The owner
/// depends on the state of the task:
///
/// * `RUNNING` A task in running state is owned by the [RunQueue] and either
///    stored in the `run_list` (when the task is not actively running) or in
///    `current+task` when it is scheduled on the CPU.
/// * `BLOCKED` A task in this state is waiting for an event to become runnable
///    again. It is owned by a wait object when in this state.
/// * `TERMINATED` The task is about to be destroyed and owned by the RunQueue.
///
/// The scheduler is cooperative. A task runs until it voluntarily calls the
/// [schedule] function.
///
/// Only when a task is in `RUNNING` or `TERMINATED` state it is assigned to a
/// specific CPU. Tasks in the `BLOCKED` state have no CPU assigned and will run
/// on the CPU where their event is triggered that makes them `RUNNING` again.

pub type TaskPointer = Arc<TaskNode>;

#[derive(Debug)]
pub struct TaskNode {
    list_link: LinkedListAtomicLink,
    runlist_link: LinkedListAtomicLink,
    pub task: RWLock<Box<Task>>,
}

// SAFETY: Send + Sync is required for Arc<TaskNode> to implement Send. The `task`
// member is Send + Sync but the intrusive_collection links are only Send. The only
// access to these is via the intrusive_adapter! generated code which does not use
// them concurrently across threads.
unsafe impl Sync for TaskNode {}

impl PartialEq for TaskNode {
    fn eq(&self, other: &Self) -> bool {
        let a = self as *const Self;
        let b = other as *const Self;
        a == b
    }
}

intrusive_adapter!(pub TaskRunListAdapter = TaskPointer: TaskNode { runlist_link: LinkedListAtomicLink });
intrusive_adapter!(pub TaskListAdapter = TaskPointer: TaskNode { list_link: LinkedListAtomicLink });

/// A RunQueue implementation that uses an RBTree to efficiently sort the priority
/// of tasks within the queue.
#[derive(Debug, Default)]
pub struct RunQueue {
    run_list: LinkedList<TaskRunListAdapter>,
    current_task: Option<TaskPointer>,
    idle_task: OnceCell<TaskPointer>,
    terminated_task: Option<TaskPointer>,
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
        }
    }

    /// Find the next task to run, which is either the task at the front of the
    /// run_list or the idle task, if the run_list is empty.
    ///
    /// # Returns
    ///
    /// Pointer to next task to run
    fn get_next_task(&mut self) -> TaskPointer {
        self.run_list
            .pop_front()
            .unwrap_or(self.idle_task.get().unwrap().clone())
    }

    /// Update state before a task is scheduled out. Non-idle tasks in RUNNING
    /// state will be put at the end of the run_list. Terminated tasks will be
    /// stored in the terminated_task field of the RunQueue and be destroyed
    /// after the task-switch.
    fn handle_task(&mut self, taskptr: TaskPointer) {
        let task = taskptr.task.lock_read();
        if task.is_running() && !task.is_idle_task() {
            self.run_list.push_back(taskptr.clone());
        } else if task.is_terminated() {
            self.terminated_task = Some(taskptr.clone());
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
        this_cpu_mut().current_stack = task.task.lock_read().stack_bounds();
        self.current_task = Some(task.clone());
        task
    }

    /// Prepares a task switch. The function checks if a task switch needs to
    /// be done and return pointers to the current and next task. It will also
    /// call handle_task() on the current task in case a task-switch is
    /// requested.
    ///
    /// # Returns
    ///
    /// None when no task-switch is needed
    /// Some() with current and next task in case a task-switch is required
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
            this_cpu_mut().current_stack = next.task.lock_read().stack_bounds();
            Some((current, next))
        } else {
            None
        }
    }

    pub fn current_task_id(&self) -> u32 {
        self.current_task
            .as_ref()
            .map_or(INITIAL_TASK_ID, |t| t.task.lock_read().get_task_id())
    }

    /// Allocates the idle task for this RunQueue. This function sets a
    /// OnceCell at the end and can thus be only called once.
    ///
    /// # Returns
    ///
    /// Ok(()) on success, SvsmError on failure
    pub fn allocate_idle_task(&self, entry: extern "C" fn()) -> Result<(), SvsmError> {
        let mut task = Task::create(entry, TASK_FLAG_SHARE_PT)?;
        task.set_idle_task();
        let node = Arc::new(TaskNode {
            list_link: LinkedListAtomicLink::default(),
            runlist_link: LinkedListAtomicLink::default(),
            task: RWLock::new(task),
        });

        // Add idle task to global task list
        TASKLIST.lock().list().push_front(node.clone());

        self.idle_task
            .set(node)
            .expect("Idle task already allocated");
        Ok(())
    }

    pub fn current_task(&self) -> TaskPointer {
        self.current_task.as_ref().unwrap().clone()
    }
}

/// Global task list
/// This contains every task regardless of affinity or run state.
#[derive(Debug)]
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
        while let Some(task_node) = cursor.get() {
            if task_node.task.lock_read().get_task_id() == id {
                return cursor.clone_pointer();
            }
            cursor.move_next();
        }
        None
    }

    fn terminate(&mut self, task_node: TaskPointer) {
        // Set the task state as terminated. If the task being terminated is the
        // current task then the task context will still need to be in scope until
        // the next schedule() has completed. Schedule will keep a reference to this
        // task until some time after the context switch.
        task_node.task.lock_write().set_task_terminated();
        let mut cursor = unsafe { self.list().cursor_mut_from_ptr(task_node.as_ref()) };
        cursor.remove();
    }
}

pub static TASKLIST: SpinLock<TaskList> = SpinLock::new(TaskList::new());

pub fn create_task(entry: extern "C" fn(), flags: u16) -> Result<TaskPointer, SvsmError> {
    let task = Task::create(entry, flags)?;
    let node = Arc::new(TaskNode {
        list_link: LinkedListAtomicLink::default(),
        runlist_link: LinkedListAtomicLink::default(),
        task: RWLock::new(task),
    });
    {
        // Ensure the tasklist lock is released before schedule() is called
        // otherwise the lock will be held when switching to a new context
        let mut tl = TASKLIST.lock();
        tl.list().push_front(node.clone());
    }
    schedule();

    Ok(node)
}

/// Check to see if the task scheduled on the current processor has the given id
pub fn is_current_task(id: u32) -> bool {
    match &this_cpu().runqueue().lock_read().current_task {
        Some(current_task) => current_task.task.lock_read().get_task_id() == id,
        None => id == INITIAL_TASK_ID,
    }
}

pub unsafe fn current_task_terminated() {
    let mut rq = this_cpu().runqueue().lock_write();
    let task_node = rq
        .current_task
        .as_mut()
        .expect("Task termination handler called when there is no current task");
    TASKLIST.lock().terminate(task_node.clone());
}

// SAFETY: This function returns a mutable raw pointer to a task. It is safe
// because this function is only used in the task switch code, which also only
// takes a single mutable reference to the next and previous tasks. Also, this
// function needs a write-lock on the TaskPointer, making sure there are no
// other mutable references.
unsafe fn task_pointer(taskptr: TaskPointer) -> *mut Task {
    let mut guard = taskptr.task.lock_write();
    let task = guard.as_mut();

    task as *mut Task
}

#[inline(always)]
unsafe fn switch_to(prev: *mut Task, next: *mut Task) {
    // Switch to new task
    asm!(
        r#"
        call switch_context
        "#,
        in("rsi") prev as u64,
        in("rdi") next as u64,
        options(att_syntax));
}

/// Initializes the [RunQueue] on the current CPU. It will switch to the idle
/// task and initialize the current_task field of the RunQueue. After this
/// function has ran it is safe to call [schedule()] on the current CPU.
pub fn schedule_init() {
    unsafe {
        let next = task_pointer(this_cpu().runqueue().lock_write().schedule_init());
        switch_to(null_mut(), next);
    }
}

/// Perform a task switch and hand the CPU over to the next task on the
/// run-list. In case the current task is terminated, it will be destroyed after
/// the switch to the next task.
pub fn schedule() {
    let work = this_cpu().runqueue().lock_write().schedule_prepare();

    // !!! Runqueue lock must be release here !!!
    if work.is_some() {
        unsafe {
            // Get current and next task
            let (current, next) = work.unwrap();

            // Get task-pointers, consuming the Arcs and release their reference
            let a = task_pointer(current);
            let b = task_pointer(next);

            // Switch tasks
            switch_to(a, b);
        }
    }

    // We're now in the context of the new task. If the previous task had terminated
    // then we can release it's reference here.
    let _ = this_cpu_mut()
        .runqueue()
        .lock_write()
        .terminated_task
        .take();
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
