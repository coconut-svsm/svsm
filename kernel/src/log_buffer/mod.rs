// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

extern crate alloc;
use core::fmt::Debug;

use crate::locking::{LockGuard, SpinLock};
use crate::string::FixedString;
use crate::types::{LINE_BUFFER_SIZE, PAGE_SIZE};
use crate::utils::StringRingBuffer;

use alloc::vec;
use alloc::vec::Vec;

const BUF_SIZE: usize = PAGE_SIZE / core::mem::size_of::<char>();

#[derive(Copy, Clone, Debug)]
pub struct LogBuffer {
    buf: StringRingBuffer<BUF_SIZE>,
}

impl LogBuffer {
    const fn new() -> Self {
        Self {
            buf: StringRingBuffer::<BUF_SIZE>::new(),
        }
    }

    pub fn migrate(&mut self, lb: &SpinLock<LogBuffer>) {
        self.buf = lb.lock().buf;
    }

    pub fn write_log(&mut self, s: &FixedString<LINE_BUFFER_SIZE>) {
        self.buf.write(s.iter());
    }

    // A method used for testing
    pub fn read_log(&mut self) -> Vec<u8> {
        if let Some(str) = self.buf.read() {
            str.as_bytes().to_vec()
        } else {
            vec![]
        }
    }
}

pub fn migrate_log_buffer(log_buf: &SpinLock<LogBuffer>) {
    LB.lock().migrate(log_buf);
}

static LB: SpinLock<LogBuffer> = SpinLock::new(LogBuffer::new());
pub fn log_buffer() -> LockGuard<'static, LogBuffer> {
    LB.lock()
}

pub fn get_lb() -> &'static SpinLock<LogBuffer> {
    &LB
}
