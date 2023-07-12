// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use super::Task;
use crate::error::SvsmError;
use crate::locking::{RWLock, SpinLock};
use alloc::boxed::Box;
use alloc::sync::Arc;
use intrusive_collections::{intrusive_adapter, LinkedList, LinkedListAtomicLink};

pub type TaskPointer = Arc<TaskNode>;

#[derive(Debug)]
pub struct TaskNode {
    list_link: LinkedListAtomicLink,
    pub task: RWLock<Box<Task>>,
}

// SAFETY: Send + Sync is required for Arc<TaskNode> to implement Send. The `task`
// member is Send + Sync but the intrusive_collection links are only Send. The only
// access to these is via the intrusive_adapter! generated code which does not use
// them concurrently across threads.
unsafe impl Sync for TaskNode {}

intrusive_adapter!(pub TaskListAdapter = Arc<TaskNode>: TaskNode { list_link: LinkedListAtomicLink });

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
}

pub static TASKLIST: SpinLock<TaskList> = SpinLock::new(TaskList::new());

pub fn create_task(
    entry: extern "C" fn(),
    flags: u16,
    affinity: Option<u32>,
) -> Result<TaskPointer, SvsmError> {
    let mut task = Task::create(entry, flags)?;
    task.set_affinity(affinity);
    let node = Arc::new(TaskNode {
        list_link: LinkedListAtomicLink::default(),
        task: RWLock::new(task),
    });
    TASKLIST.lock().list().push_front(node.clone());
    Ok(node)
}
