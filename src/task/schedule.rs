// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use core::ptr::null_mut;

use super::Task;
use super::{tasks::TaskRuntime, TaskState, INITIAL_TASK_ID};
use crate::cpu::percpu::{this_cpu, this_cpu_mut};
use crate::error::SvsmError;
use crate::locking::{RWLock, SpinLock};
use alloc::boxed::Box;
use alloc::sync::Arc;
use intrusive_collections::{
    intrusive_adapter, Bound, KeyAdapter, LinkedList, LinkedListAtomicLink, RBTree,
    RBTreeAtomicLink,
};

pub type TaskPointer = Arc<TaskNode>;

#[derive(Debug)]
pub struct TaskNode {
    tree_link: RBTreeAtomicLink,
    list_link: LinkedListAtomicLink,
    pub task: RWLock<Box<Task>>,
}

// SAFETY: Send + Sync is required for Arc<TaskNode> to implement Send. The `task`
// member is Send + Sync but the intrusive_collection links are only Send. The only
// access to these is via the intrusive_adapter! generated code which does not use
// them concurrently across threads.
unsafe impl Sync for TaskNode {}

intrusive_adapter!(pub TaskTreeAdapter = TaskPointer: TaskNode { tree_link: RBTreeAtomicLink });
intrusive_adapter!(pub TaskListAdapter = TaskPointer: TaskNode { list_link: LinkedListAtomicLink });

impl<'a> KeyAdapter<'a> for TaskTreeAdapter {
    type Key = u64;
    fn get_key(&self, node: &'a TaskNode) -> u64 {
        node.task.lock_read().runtime.value()
    }
}

#[derive(Debug)]
struct TaskSwitch {
    previous_task: Option<TaskPointer>,
    next_task: Option<TaskPointer>,
}

/// A RunQueue implementation that uses an RBTree to efficiently sort the priority
/// of tasks within the queue.
#[derive(Debug)]
pub struct RunQueue {
    tree: Option<RBTree<TaskTreeAdapter>>,
    current_task: Option<TaskPointer>,
    terminated_task: Option<TaskPointer>,
    id: u32,
    task_switch: TaskSwitch,
}

impl RunQueue {
    /// Create a new runqueue for an id. The id would normally be set
    /// to the APIC ID of the CPU that owns the runqueue and is used to
    /// determine the affinity of tasks.
    pub const fn new(id: u32) -> Self {
        Self {
            tree: None,
            current_task: None,
            terminated_task: None,
            id,
            task_switch: TaskSwitch {
                previous_task: None,
                next_task: None,
            },
        }
    }

    fn tree(&mut self) -> &mut RBTree<TaskTreeAdapter> {
        self.tree
            .get_or_insert_with(|| RBTree::new(TaskTreeAdapter::new()))
    }

    pub fn get_task(&self, id: u32) -> Option<TaskPointer> {
        if let Some(task_tree) = &self.tree {
            let mut cursor = task_tree.front();
            while let Some(task_node) = cursor.get() {
                if task_node.task.lock_read().id == id {
                    return cursor.clone_pointer();
                }
                cursor.move_next();
            }
        }
        None
    }

    pub fn current_task_id(&self) -> u32 {
        self.current_task
            .as_ref()
            .map_or(INITIAL_TASK_ID, |t| t.task.lock_read().id)
    }

    /// Determine the next task to run on the vCPU that owns this instance.
    /// Populates self.task_switchwith the next task and the previous task. If both
    /// are None then the existing task remains in scope.
    ///
    /// Note that this function does not actually perform the task switch. This is
    /// because it holds a mutable reference to self that must be released before
    /// the task switch occurs. Call this function from a global function that releases
    /// the reference before performing the task switch.
    ///
    /// # Returns
    ///
    /// Pointers to the next task and the previous task.
    ///
    /// If the next task pointer is null_mut() then no task switch is required and the
    /// caller must release the runqueue lock.
    ///
    /// If the next task pointer is not null_mut() then the caller must call
    /// next_task->set_current(prev_task) with the runqueue lock still held.
    fn schedule(&mut self) -> (*mut Task, *mut Task) {
        self.task_switch.previous_task = None;
        self.task_switch.next_task = None;

        // Update the state of the current task. This will change the runtime value which
        // is used as a key in the RB tree therefore we need to remove and reinsert the
        // task.
        let prev_task_node = self.update_current_task();

        // Find the task with the lowest runtime. The tree only contains running tasks that
        // are to be scheduled on this vCPU.
        let cursor = self.tree().lower_bound(Bound::Unbounded);

        // The cursor will now be on the next task to schedule. There should always be
        // a candidate task unless the current cpu task terminated. For now, don't support
        // termination of the initial thread which means there will always be a task to schedule
        let next_task_node = cursor.clone_pointer().expect("No task to schedule on CPU");
        self.current_task = Some(next_task_node.clone());

        // Lock the current and next tasks and keep track of the lock state by adding references
        // into the structure itself. This allows us to retain the lock over the context switch
        // and unlock the tasks before returning to the new context.
        let prev_task_ptr = if let Some(prev_task_node) = prev_task_node {
            // If the next task is the same as the current one then we have nothing to do.
            if prev_task_node.task.lock_read().id == next_task_node.task.lock_read().id {
                return (null_mut(), null_mut());
            }
            self.task_switch.previous_task = Some(prev_task_node.clone());
            unsafe { (*prev_task_node.task.lock_write_direct()).as_mut() }
        } else {
            null_mut()
        };
        self.task_switch.next_task = Some(next_task_node.clone());
        let next_task_ptr = unsafe { (*next_task_node.task.lock_write_direct()).as_mut() };

        (next_task_ptr, prev_task_ptr)
    }

    fn update_current_task(&mut self) -> Option<TaskPointer> {
        let task_node = self.current_task.take()?;
        let task_state = {
            let mut task = task_node.task.lock_write();
            task.runtime.schedule_out();
            task.state
        };

        if task_state == TaskState::TERMINATED {
            // The current task has terminated. Make sure it doesn't get added back
            // into the runtime tree, but also we need to make sure we keep a
            // reference to the task because the current stack is owned by it.
            // Put it in a holding location which will be cleared by the next
            // active task.
            unsafe {
                self.deallocate(task_node.clone());
            }
            self.terminated_task = Some(task_node);
            None
        } else {
            // Reinsert the node into the tree so the position is updated with the new runtime
            let mut task_cursor = unsafe { self.tree().cursor_mut_from_ptr(task_node.as_ref()) };
            task_cursor.remove();
            self.tree().insert(task_node.clone());
            Some(task_node)
        }
    }

    /// Helper function that determines if a task is a candidate for allocating
    /// to a CPU
    fn is_cpu_candidate(&self, t: &Task) -> bool {
        (t.state == TaskState::RUNNING)
            && t.allocation.is_none()
            && t.affinity.map_or(true, |a| a == self.id)
    }

    /// Iterate through all unallocated tasks and find a suitable candidates
    /// for allocating to this queue
    pub fn allocate(&mut self) {
        let mut tl = TASKLIST.lock();
        let lowest_runtime = if let Some(t) = self.tree().lower_bound(Bound::Unbounded).get() {
            t.task.lock_read().runtime.value()
        } else {
            0
        };
        let mut cursor = tl.list().cursor_mut();
        while !cursor.peek_next().is_null() {
            cursor.move_next();
            // Filter on running, unallocated tasks that either have no affinity
            // or have an affinity for this CPU ID
            if let Some(task_node) = cursor
                .get()
                .filter(|task_node| self.is_cpu_candidate(task_node.task.lock_read().as_ref()))
            {
                {
                    let mut t = task_node.task.lock_write();
                    // Now we have the lock, check again that the task has not been allocated
                    // to another runqueue between the filter above and us taking the lock.
                    if t.allocation.is_some() {
                        continue;
                    }
                    t.allocation = Some(self.id);
                    t.runtime.set(lowest_runtime);
                }
                self.tree()
                    .insert(cursor.as_cursor().clone_pointer().unwrap());
            }
        }
    }

    /// Release the spinlock on the previous and next tasks following a task switch.
    ///
    /// # Safety
    ///
    /// The caller must ensure that any access to the previous or next tasks via
    /// the pointers returned by [`Self::schedule()`] are no longer used after calling this
    /// function. The RWLocks protecting the pointers are released by this function
    /// meaning that further access to the pointers will cause undefined behaviour.
    unsafe fn unlock_tasks(&mut self) {
        if let Some(previous_task) = self.task_switch.previous_task.as_ref() {
            unsafe {
                previous_task.task.unlock_write_direct();
            }
            self.task_switch.previous_task = None;
        }
        if let Some(next_task) = self.task_switch.next_task.as_ref() {
            unsafe {
                next_task.task.unlock_write_direct();
            }
            self.task_switch.next_task = None;
        }
    }

    /// Deallocate a task from a per CPU runqueue but leave it in the global task list
    /// where it can be reallocated if still in the RUNNING state.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the function is passed a valid task_node as
    /// this function dereferences the pointer contained within the task_node. A
    /// [`TaskPointer`] uses an [`Arc`] to manage the lifetime of the contained pointer
    /// making it difficult to pass an invalid pointer to this function.
    unsafe fn deallocate(&mut self, task_node: TaskPointer) {
        let mut cursor = self.tree().cursor_mut_from_ptr(task_node.as_ref());
        cursor.remove();
        task_node.task.lock_write().allocation = None;
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
            if task_node.task.lock_read().id == id {
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
        task_node.task.lock_write().state = TaskState::TERMINATED;
        let mut cursor = unsafe { self.list().cursor_mut_from_ptr(task_node.as_ref()) };
        cursor.remove();
    }
}

pub static TASKLIST: SpinLock<TaskList> = SpinLock::new(TaskList::new());

fn task_switch_hook(_: &Task) {
    // Then unlock the spinlocks that protect the previous and new tasks.

    // SAFETY: Unlocking the tasks is a safe operation at this point because
    // we do not use the task pointers beyond the task switch itself which
    // is complete at the time of this hook.
    unsafe {
        this_cpu_mut().runqueue().lock_write().unlock_tasks();
    }
}

pub fn create_task(
    entry: extern "C" fn(),
    flags: u16,
    affinity: Option<u32>,
) -> Result<TaskPointer, SvsmError> {
    let mut task = Task::create(entry, flags)?;
    task.set_affinity(affinity);
    task.set_on_switch_hook(Some(task_switch_hook));
    let node = Arc::new(TaskNode {
        tree_link: RBTreeAtomicLink::default(),
        list_link: LinkedListAtomicLink::default(),
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
        Some(current_task) => current_task.task.lock_read().id == id,
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

pub fn schedule() {
    this_cpu_mut().allocate_tasks();

    let (next_task, prev_task) = this_cpu().runqueue().lock_write().schedule();
    if !next_task.is_null() {
        unsafe {
            (*next_task).set_current(prev_task);
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
