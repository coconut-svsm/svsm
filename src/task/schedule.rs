// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use core::cell::RefCell;

use super::Task;
use super::{tasks::TaskRuntime, TaskState, INITIAL_TASK_ID};
use crate::cpu::percpu::{this_cpu, this_cpu_mut};
use crate::error::SvsmError;
use crate::locking::SpinLock;
use alloc::boxed::Box;
use alloc::rc::Rc;
use intrusive_collections::{intrusive_adapter, Bound, KeyAdapter, RBTree, RBTreeLink};

pub type TaskPointer = Rc<TaskNode>;

pub struct TaskNode {
    link: RBTreeLink,
    pub task: RefCell<Box<Task>>,
}

intrusive_adapter!(pub TaskNodeAdapter = Rc<TaskNode>: TaskNode { link: RBTreeLink });
impl<'a> KeyAdapter<'a> for TaskNodeAdapter {
    type Key = u64;
    fn get_key(&self, node: &'a TaskNode) -> u64 {
        node.task.borrow().runtime.value()
    }
}

pub struct TaskRBTree {
    tree: Option<RBTree<TaskNodeAdapter>>,
}

impl TaskRBTree {
    pub fn tree(&mut self) -> &mut RBTree<TaskNodeAdapter> {
        self.tree
            .get_or_insert_with(|| RBTree::<TaskNodeAdapter>::new(TaskNodeAdapter::new()))
    }

    pub fn get_task(&self, id: u32) -> Option<Rc<TaskNode>> {
        let mut cursor = self.tree.as_ref().unwrap().front();
        while let Some(task_node) = cursor.get() {
            if task_node.task.borrow().id == id {
                return cursor.clone_pointer();
            }
            cursor.move_next();
        }
        None
    }
}

pub static TASKS: SpinLock<TaskRBTree> = SpinLock::new(TaskRBTree { tree: None });

///
/// Each processor that is assigned to run tasks must call this function
/// before further tasks can be scheduled onto the CPU by schedule().
///
pub fn create_initial_task(
    entry: extern "C" fn(),
    flags: u16,
    affinity: Option<u32>,
) -> Result<(), SvsmError> {
    if this_cpu().current_task.is_some() {
        return Err(SvsmError::Task);
    }
    let task_node = create_task(entry, flags, affinity)?;
    this_cpu_mut().current_task = Some(task_node.clone());

    let task_ptr = {
        let task_ptr = task_node.task.as_ptr();
        let mut task = task_node.task.borrow_mut();
        if task.state != TaskState::RUNNING {
            panic!("Attempt to launch a non-running initial task");
        }
        task.state = TaskState::SCHEDULED;
        task_ptr
    };
    unsafe { (*task_ptr).set_current(core::ptr::null_mut()) };
    Ok(())
}

pub fn create_task(
    entry: extern "C" fn(),
    flags: u16,
    affinity: Option<u32>,
) -> Result<TaskPointer, SvsmError> {
    let mut task = Task::create(entry, flags)?;
    task.set_affinity(affinity);
    let node = Rc::new(TaskNode {
        link: RBTreeLink::default(),
        task: RefCell::new(task),
    });
    let node_ret = node.clone();
    TASKS.lock().tree().insert(node);
    Ok(node_ret)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn close_task(task: TaskPointer) -> Result<(), SvsmError> {
    // All tasks are protected via the task tree lock
    let mut tl = TASKS.lock();
    let mut cursor = unsafe { tl.tree().cursor_mut_from_ptr(task.as_ref()) };
    if cursor
        .get()
        .filter(|task_node| task_node.task.borrow().state == TaskState::TERMINATED)
        .is_none()
    {
        Err(SvsmError::Task)
    } else {
        cursor.remove().ok_or(SvsmError::Task).map(|_| ())
    }
}

/// Check to see if the task scheduled on the current processor has the given id
pub fn is_current_task(id: u32) -> bool {
    match &this_cpu().current_task {
        Some(current_task) => current_task.task.borrow().id == id,
        None => id == INITIAL_TASK_ID,
    }
}

fn update_current_task(tree: &mut RBTree<TaskNodeAdapter>) -> TaskPointer {
    // This function leaves the CPU in an invalid state as it takes the current
    // task, replacing it with None. The caller must assign a new task or reassign
    // the current task to the CPU before resuming.
    let task_ptr = this_cpu_mut().current_task.take().unwrap();
    let mut task_cursor = unsafe { tree.cursor_mut_from_ptr(task_ptr.as_ref()) };
    let task_node = task_cursor.remove().unwrap();
    {
        let mut task = task_node.task.borrow_mut();
        if task.state == TaskState::SCHEDULED {
            task.state = TaskState::RUNNING;
        }

        // If this is the first time the task is considered for scheduling then
        // take the minimum value from the tree to ensure the new task is not
        // allocated all of the CPU until it catches up.
        if task.runtime.first() {
            let cursor = tree.lower_bound(Bound::Included(&0));
            if let Some(t) = cursor.get() {
                task.runtime.set(t.task.borrow().runtime.value());
            }
        }
        task.runtime.schedule_out();
    }
    tree.insert(task_node);
    task_ptr
}

pub fn schedule() {
    let (next_task, current_task) = {
        let mut tl = TASKS.lock();

        // Update the state of the current task. This will change the runtime value which
        // is used as a key in the RB tree therefore we need to remove and reinsert the
        // task.
        let tree = tl.tree();
        let current_task_node = update_current_task(tree);

        // Find the task with the lowest runtime that is eligible to run
        // on this CPU
        let mut cursor = tree.lower_bound(Bound::Included(&0));
        while let Some(task_node) = cursor.get() {
            let candidate_task = task_node.task.borrow();
            // If the runtime of the candidate task is greater than the task that was
            // current running on the CPU then don't switch
            if candidate_task.state == TaskState::RUNNING
                && candidate_task
                    .affinity
                    .map_or(true, |a| a == this_cpu().get_apic_id())
            {
                break;
            }
            cursor.move_next();
        }

        // The cursor will now be on the next task to schedule. There should always be
        // a candidate task unless the current cpu task terminated. For now, don't support
        // termination of the initial thread which means there will always be a task to schedule
        let next_task_node = cursor.clone_pointer().expect("No task to schedule on CPU");
        this_cpu_mut().current_task = Some(next_task_node.clone());

        // Update the task we are switching to. Note that the next task may be
        // the same as the current task so ensure we don't mutably borrow it twice
        // by restricting the scope of the borrow_mut below.
        let next_task_ptr = next_task_node.task.as_ptr();
        let next_task_id = {
            let mut next_task = next_task_node.task.borrow_mut();
            next_task.state = TaskState::SCHEDULED;
            next_task.runtime.schedule_in();
            next_task.id
        };

        let mut current_task = current_task_node.task.borrow_mut();
        let current_task_ptr = current_task.as_mut() as *mut Task;
        if next_task_id == current_task.id {
            (None, core::ptr::null_mut())
        } else {
            (Some(next_task_ptr), current_task_ptr)
        }
    };
    if let Some(next_task) = next_task {
        unsafe { (*next_task).set_current(current_task) };
    }
}
