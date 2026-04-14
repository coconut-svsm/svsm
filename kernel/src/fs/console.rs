// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use super::{Buffer, File, FsError};
use crate::error::SvsmError;
use crate::fs::StdoutBuffer;
use crate::locking::SpinLock;
use alloc::string::String;

#[derive(Debug)]
struct ConsoleBuffer {
    cb: StdoutBuffer,
}

impl ConsoleBuffer {
    fn new(component: String) -> Self {
        Self {
            cb: StdoutBuffer::new(component),
        }
    }
}

#[derive(Debug)]
pub struct ConsoleFile {
    buffer: SpinLock<ConsoleBuffer>,
}

impl ConsoleFile {
    pub fn new(component: String) -> Self {
        Self {
            buffer: SpinLock::new(ConsoleBuffer::new(component)),
        }
    }
}

impl Default for ConsoleFile {
    fn default() -> Self {
        Self::new(String::new())
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
        self.buffer.lock().cb.stdout_write(buf, false)
    }

    fn write_buffer(&self, buffer: &dyn Buffer, _offset: usize) -> Result<usize, SvsmError> {
        self.buffer.lock().cb.stdout_write_buffer(buffer, false)
    }

    fn truncate(&self, _size: usize) -> Result<usize, SvsmError> {
        Err(SvsmError::FileSystem(FsError::not_supported()))
    }

    fn size(&self) -> usize {
        0
    }
}
