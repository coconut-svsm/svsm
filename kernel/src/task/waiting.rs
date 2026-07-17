// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use intrusive_collections::LinkedList;

use super::tasks::{TaskPointer, TaskWaitListAdapter};

/// A queue of tasks waiting for a single event. Multiple tasks may wait
/// simultaneously.
#[derive(Debug)]
pub struct WaitQueue {
    waiters: LinkedList<TaskWaitListAdapter>,
}

impl WaitQueue {
    pub fn new() -> Self {
        Self {
            waiters: LinkedList::new(TaskWaitListAdapter::new()),
        }
    }

    /// Register `current_task` as a waiter on this queue. The task is
    /// immediately marked as blocked. Multiple callers may wait concurrently.
    pub fn wait_for_event(&mut self, current_task: TaskPointer) {
        current_task.set_task_blocked();
        self.waiters.push_back(current_task);
    }

    /// Wake all waiting tasks. Returns the waiters so the caller can unlink
    /// and schedule each one.
    pub fn wakeup(&mut self, wake_all: bool) -> LinkedList<TaskWaitListAdapter> {
        assert!(wake_all);

        self.waiters.take()
    }
}
