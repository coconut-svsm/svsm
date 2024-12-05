// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use super::{Buffer, File, FileHandle, FsError};
use crate::console::console_write;
use crate::cpu::percpu::current_task;
use crate::error::SvsmError;
use crate::fs::obj::FsObj;
use crate::locking::SpinLock;
use crate::syscall::Obj;
use alloc::string::String;
use alloc::sync::Arc;

// With the value of 224 the ConsoleBuffer struct will be exactly 256 bytes
// large, avoiding memory waste due to internal fragmentation.
const CONSOLE_LINE_BUFFER_SIZE: usize = 224;

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
        let newline: u8 = '\n'.try_into().unwrap();

        if self.fill + 1 == CONSOLE_LINE_BUFFER_SIZE {
            self.buffer[self.fill] = newline;
            self.fill += 1;
            self.flush();
        }

        let index = self.fill;
        self.buffer[index] = b;
        self.fill += 1;
        if b == newline {
            self.flush();
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

pub fn stdout_open() -> Arc<dyn Obj> {
    let console_file: Arc<dyn File> = Arc::new(ConsoleFile::new());

    // Stdout is write-only.
    Arc::new(FsObj::new_file(FileHandle::new(&console_file, false, true)))
}
