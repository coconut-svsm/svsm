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

use alloc::string::ToString;
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
        self.buf.write(&s.to_string());
    }

    pub fn read_log(&mut self) -> Vec<u8> {
        if let Some(str) = self.buf.read() {
            str.as_bytes().to_vec()
        } else {
            vec![]
        }
    }
}

static mut LB: SpinLock<LogBuffer> = SpinLock::new(LogBuffer::new());
pub fn log_buffer() -> LockGuard<'static, LogBuffer> {
    // SAFETY: Mutation of the mutable LB global variable is via the
    // `[SpinLock::lock()]` function. SpinLock is Sync meaning the mutation
    // is safe even if this function is called simulataneously in
    // different threads. Also, the mutation of the global variable
    // by the returned `[LockGuard]` is safe for the same reason, meaning
    // this function does not need to be marked unsafe.
    unsafe { LB.lock() }
}
