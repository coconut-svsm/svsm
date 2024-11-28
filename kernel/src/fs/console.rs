// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use super::{Buffer, File, FsError};
use crate::console::console_write;
use crate::cpu::percpu::current_task;
use crate::error::SvsmError;
use crate::locking::SpinLock;
use alloc::string::String;

const CONSOLE_LINE_BUFFER_SIZE: usize = 256;

#[derive(Debug)]
struct ConsoleBuffer {
    prefix: String,
    buffer: [u8; CONSOLE_LINE_BUFFER_SIZE],
    fill: usize,
}

impl ConsoleBuffer {
    fn new() -> Self {
        let task = current_task();
        let task_name = task.get_task_name();
        let mut prefix = String::from("[");
        prefix.push_str(task_name.as_str());
        prefix.push_str("] ");
        Self {
            prefix,
            buffer: [0u8; CONSOLE_LINE_BUFFER_SIZE],
            fill: 0,
        }
    }

    fn push(&mut self, b: u8) {
        let index = self.fill;
        self.fill += 1;
        let newline: u8 = '\n'.try_into().unwrap();
        if self.fill == CONSOLE_LINE_BUFFER_SIZE {
            self.buffer[index] = newline; // Newline
            self.flush();
            self.push(b);
        } else {
            self.buffer[index] = b;
            if b == newline {
                self.flush();
            }
        }
    }

    pub fn flush(&mut self) {
        console_write(self.prefix.as_bytes());
        console_write(&self.buffer[..self.fill]);
        self.fill = 0;
    }
}

#[derive(Debug)]
pub struct ConsoleFile {
    buffer: SpinLock<ConsoleBuffer>,
}

impl ConsoleFile {
    pub fn new() -> Self {
        Self {
            buffer: SpinLock::new(ConsoleBuffer::new()),
        }
    }
}

impl Default for ConsoleFile {
    fn default() -> Self {
        Self::new()
    }
}

impl File for ConsoleFile {
    fn read(&self, _buf: &mut [u8], _offset: usize) -> Result<usize, SvsmError> {
        Ok(0)
    }

    fn read_buffer(&self, _buffer: &mut dyn Buffer, _offset: usize) -> Result<usize, SvsmError> {
        Ok(0)
    }

    fn write(&self, buf: &[u8], _offset: usize) -> Result<usize, SvsmError> {
        let mut console = self.buffer.lock();

        for c in buf.iter() {
            console.push(*c);
        }

        Ok(buf.len())
    }

    fn write_buffer(&self, buffer: &dyn Buffer, _offset: usize) -> Result<usize, SvsmError> {
        let len = buffer.size();
        let mut offset: usize = 0;

        while offset < len {
            let mut kernel_buffer: [u8; 16] = [0u8; 16];
            let read = buffer.read_buffer(&mut kernel_buffer, offset)?;
            self.write(&kernel_buffer[0..read], 0)?;
            offset += read;
        }

        Ok(offset)
    }

    fn truncate(&self, _size: usize) -> Result<usize, SvsmError> {
        Err(SvsmError::FileSystem(FsError::not_supported()))
    }

    fn size(&self) -> usize {
        0
    }
}
