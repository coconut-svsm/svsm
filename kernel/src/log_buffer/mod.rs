// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

#[cfg(test)]
extern crate alloc;
use core::fmt::Debug;

use crate::locking::{LockGuard, SpinLock};
use crate::string::FixedString;

use crate::types::LINE_BUFFER_SIZE;
#[cfg(not(test))]
use crate::types::PAGE_SIZE;
use crate::utils::StringRingBuffer;

#[cfg(test)]
use alloc::vec;
#[cfg(test)]
use alloc::vec::Vec;

#[cfg(not(test))]
const BUF_SIZE: usize = PAGE_SIZE / core::mem::size_of::<char>();
#[cfg(test)]
const BUF_SIZE: usize = 64;

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

    #[cfg(test)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::LINE_BUFFER_SIZE;

    #[test]
    fn test_read_write_normal() {
        let mut fs = FixedString::<LINE_BUFFER_SIZE>::new();
        for i in 1..=LINE_BUFFER_SIZE {
            fs.push(char::from_u32(i as u32).unwrap());
        }

        let mut lb = LogBuffer::new();
        lb.write_log(&fs);

        let v = lb.read_log();
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

        let mut lb = LogBuffer::new();
        lb.write_log(&fs);

        let v = lb.read_log();
        assert_eq!(v.len(), LINE_BUFFER_SIZE / 2);
        for i in 1..=v.len() {
            assert_eq!(i as u8, v[i - 1]);
        }

        fs.clear();
        for i in LINE_BUFFER_SIZE / 2..LINE_BUFFER_SIZE {
            fs.push(char::from_u32((i + 1) as u32).unwrap());
        }

        lb.write_log(&fs);

        let v = lb.read_log();
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

        let mut lb = LogBuffer::new();
        lb.write_log(&fs);

        let v = lb.read_log();
        assert_eq!(v.len(), LINE_BUFFER_SIZE / 2);
        for i in 1..=v.len() {
            assert_eq!(i as u8, v[i - 1]);
        }

        fs.clear();
        for i in 1..=LINE_BUFFER_SIZE {
            let val = (i + LINE_BUFFER_SIZE / 2) as u32;
            fs.push(char::from_u32(val).unwrap());
        }

        lb.write_log(&fs);

        let v = lb.read_log();
        assert_eq!(v.len(), LINE_BUFFER_SIZE);
        for i in 1..v.len() {
            let val = (i + LINE_BUFFER_SIZE / 2) as u8;
            assert_eq!(val, v[i - 1]);
        }
    }

    #[test]
    fn test_read_empty_buffer() {
        let mut lb = LogBuffer::new();
        let v = lb.read_log();
        assert_eq!(v.len(), 0);
    }
}
