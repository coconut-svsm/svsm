// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::tasks::TaskPointer;
use super::{schedule, schedule_task};

use crate::cpu::percpu::current_task;

#[derive(Debug)]
pub struct WaitQueue {
    waiter: Option<TaskPointer>,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self { waiter: None }
    }

    pub fn wait_for_event(&mut self) {
        assert!(self.waiter.is_none());

        let task = current_task();

        task.set_task_blocked();
        self.waiter = Some(task);

        schedule();
    }

    pub fn wakeup(&mut self) {
        if self.waiter.is_some() {
            let task = self.waiter.take().unwrap();
            schedule_task(task);
        }
    }
}
