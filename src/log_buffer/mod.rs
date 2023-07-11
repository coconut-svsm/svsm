// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

extern crate alloc;
use crate::locking::SpinLock;
use crate::types::PAGE_SIZE;
use alloc::vec::Vec;

const BUF_SIZE: usize = PAGE_SIZE;

#[derive(Clone, Copy, Debug)]
struct LogBufferState {
    tail: usize,
    head: usize,
    full: bool,
}

impl LogBufferState {
    pub const fn new(tail: usize, head: usize, full: bool) -> Self {
        LogBufferState { tail, head, full }
    }

    pub fn update_for_write(&mut self, len: usize) -> usize {
        let current_head = self.head;
        self.head = (current_head + len) % BUF_SIZE;

        let place_left = if current_head >= self.tail {
            BUF_SIZE - current_head + self.tail
        } else {
            self.tail - current_head
        };

        if place_left <= len {
            self.full = true;
        }

        /* update the tail offset if this write results
         *  in a full buffer.
         */
        if self.full {
            self.tail = self.head;
        }

        current_head
    }

    pub fn update_for_read(&mut self) {
        self.tail = self.head;
        self.full = false;
    }
}

#[derive(Copy, Clone, Debug)]
pub struct LogBuffer {
    buf: [u8; BUF_SIZE],
    state: LogBufferState,
}

impl LogBuffer {
    const fn new() -> Self {
        Self {
            buf: [0; BUF_SIZE],
            state: LogBufferState::new(0, 0, false),
        }
    }

    pub fn migrate(&mut self, log_buf_src: &Self) {
        self.state = log_buf_src.state;
        self.buf = log_buf_src.buf;
    }

    pub fn write_log(&mut self, s: &[u8]) {
        let len = s.len();
        let mut head = self.state.update_for_write(len);

        for b in s.iter() {
            self.buf[head] = *b;
            head = (head + 1) % BUF_SIZE;
        }
    }

    pub fn read_log(&mut self) -> Vec<u8> {
        let mut ret: Vec<u8>;
        let st = self.state;

        if st.head == st.tail && !st.full {
            /* Buffer is empty */
            ret = Vec::new();
        } else if st.head > st.tail && !st.full {
            ret = self.buf[st.tail..st.head].to_vec();
        } else {
            ret = self.buf[st.tail..].to_vec();
            ret.extend_from_slice(&self.buf[..st.head]);
        }

        self.state.update_for_read();

        ret
    }
}

