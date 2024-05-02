// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::tasks::TaskPointer;

#[derive(Debug, Default)]
pub struct WaitQueue {
    waiter: Option<TaskPointer>,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self { waiter: None }
    }

    pub fn wait_for_event(&mut self, current_task: TaskPointer) {
        assert!(self.waiter.is_none());

        current_task.set_task_blocked();
        self.waiter = Some(current_task);
    }

    pub fn wakeup(&mut self) -> Option<TaskPointer> {
        self.waiter.take()
    }
}
