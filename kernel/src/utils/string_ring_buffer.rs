// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

extern crate alloc;

use alloc::string::String;
use core::cmp::min;
use core::fmt::Debug;

#[derive(Copy, Clone, Debug)]
pub struct StringRingBuffer<const T: usize> {
    data: [char; T],
    tail: usize,
    head: usize,
    empty: bool,
}

impl<const T: usize> StringRingBuffer<T> {
    pub const fn new() -> Self {
        Self {
            data: ['\0'; T],
            tail: 0,
            head: 0,
            empty: true,
        }
    }

    pub fn write(&mut self, s: &str) {
        s.chars().for_each(|c| self.write_char(c));
    }

    pub fn write_char(&mut self, c: char) {
        let full = !self.empty && (self.head == self.tail);
        self.data[self.head] = c;
        self.head = (self.head + 1) % T;
        if full {
            self.tail = self.head;
        }
        self.empty = false;
    }

    pub fn read_char(&mut self) -> Option<char> {
        if !self.empty {
            let c = self.data[self.tail];
            self.tail = (self.tail + 1) % T;
            self.empty = self.tail == self.head;
            Some(c)
        } else {
            None
        }
    }

    pub fn read(&mut self) -> Option<String> {
        if !self.empty {
            let len = if self.head == self.tail {
                T
            } else {
                ((self.head + T) - self.tail) % T
            };
            let end_len = min(T - self.tail, len);
            let start_len = len - end_len;

            let a: String = self.data[self.tail..(self.tail + end_len)].iter().collect();
            let b: String = self.data[0..start_len].iter().collect();
            self.tail = self.head;
            self.empty = true;
            Some(a + &b)
        } else {
            None
        }
    }
}

#[test]
fn test_ring_one_string() {
    let mut ring = StringRingBuffer::<32>::new();
    ring.write("Hello");

    let s = ring.read();
    assert!(s.is_some());
    assert_eq!(s.unwrap(), "Hello");
}

#[test]
fn test_ring_two_strings() {
    let mut ring = StringRingBuffer::<32>::new();
    ring.write("Hello");
    ring.write("Hello");

    let s = ring.read();
    assert!(s.is_some());
    assert_eq!(s.unwrap(), "HelloHello");
}

#[test]
fn test_ring_wrap() {
    let mut ring = StringRingBuffer::<32>::new();
    ring.write("0000000000000000");
    ring.write("1111111111111111");
    ring.write("2222222222222222");

    let s = ring.read();
    assert!(s.is_some());
    assert_eq!(s.unwrap(), "11111111111111112222222222222222");
}

#[test]
fn test_ring_overflow() {
    let mut ring = StringRingBuffer::<32>::new();
    ring.write("000000000000000011111111111111112222222222222222");

    let s = ring.read();
    assert!(s.is_some());
    assert_eq!(s.unwrap(), "11111111111111112222222222222222");
}

#[test]
fn test_ring_second_read() {
    let mut ring = StringRingBuffer::<32>::new();
    ring.write("Testing");

    let s = ring.read();
    assert!(s.is_some());
    assert_eq!(s.unwrap(), "Testing");
    let s = ring.read();
    assert!(s.is_none());
}

#[test]
fn test_ring_second_wrwr() {
    let mut ring = StringRingBuffer::<32>::new();
    ring.write("Testing1");
    let s = ring.read();
    assert!(s.is_some());
    assert_eq!(s.unwrap(), "Testing1");

    ring.write("Testing2");
    let s = ring.read();
    assert!(s.is_some());
    assert_eq!(s.unwrap(), "Testing2");
}
