// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

extern crate alloc;
use core::fmt::Debug;

use crate::locking::{LockGuard, SpinLock};
use crate::string::FixedString;

#[cfg(not(test))]
use crate::types::{LINE_BUFFER_SIZE, PAGE_SIZE};
use crate::utils::StringRingBuffer;

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

#[cfg(not(test))]
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

pub fn migrate_log_buffer(log_buf: &SpinLock<LogBuffer>) {
    unsafe { LB.lock().migrate(log_buf) };
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

pub fn get_lb() -> &'static SpinLock<LogBuffer> {
    unsafe { &LB }
}

#[cfg(test)]
const BUF_SIZE: usize = 64;

#[cfg(test)]
use crate::types::LINE_BUFFER_SIZE;

#[test]
fn test_read_write_normal() {
    let mut fs = FixedString::<LINE_BUFFER_SIZE>::new();
    for i in 1..=LINE_BUFFER_SIZE {
        fs.push(char::from_u32(i as u32).unwrap());
    }

    log_buffer().write_log(&fs);

    let v = log_buffer().read_log();
    assert_eq!(v.len(), LINE_BUFFER_SIZE);
    for i in 1..=v.len() {
        assert_eq!(i as u8, v[i - 1]);
    }
}

#[test]
fn test_read_write_interleaved() {
    let mut fs = FixedString::<LINE_BUFFER_SIZE>::new();
    for i in 1..=LINE_BUFFER_SIZE / 2 {
        fs.push(char::from_u32(i as u32).unwrap());
    }

    log_buffer().write_log(&fs);

    let v = log_buffer().read_log();
    assert_eq!(v.len(), LINE_BUFFER_SIZE / 2);
    for i in 1..=v.len() {
        assert_eq!(i as u8, v[i - 1]);
    }

    fs.clear();
    for i in LINE_BUFFER_SIZE / 2..LINE_BUFFER_SIZE {
        fs.push(char::from_u32((i + 1) as u32).unwrap());
    }

    log_buffer().write_log(&fs);

    let v = log_buffer().read_log();
    assert_eq!(v.len(), LINE_BUFFER_SIZE / 2);
    for i in 1..v.len() {
        let val = (i + LINE_BUFFER_SIZE / 2) as u8;
        assert_eq!(val, v[i - 1]);
    }
}

#[test]
fn test_write_wrap_around() {
    let mut fs = FixedString::<LINE_BUFFER_SIZE>::new();
    for i in 1..=LINE_BUFFER_SIZE / 2 {
        fs.push(char::from_u32(i as u32).unwrap());
    }

    log_buffer().write_log(&fs);

    let v = log_buffer().read_log();
    assert_eq!(v.len(), LINE_BUFFER_SIZE / 2);
    for i in 1..=v.len() {
        assert_eq!(i as u8, v[i - 1]);
    }

    fs.clear();
    for i in 1..=LINE_BUFFER_SIZE {
        let val = (i + LINE_BUFFER_SIZE / 2) as u32;
        fs.push(char::from_u32(val).unwrap());
    }

    log_buffer().write_log(&fs);

    let v = log_buffer().read_log();
    assert_eq!(v.len(), LINE_BUFFER_SIZE);
    for i in 1..v.len() {
        let val = (i + LINE_BUFFER_SIZE / 2) as u8;
        assert_eq!(val, v[i - 1]);
    }
}

#[test]
fn test_read_empty_buffer() {
    let v = log_buffer().read_log();
    assert_eq!(v.len(), 0);
}
