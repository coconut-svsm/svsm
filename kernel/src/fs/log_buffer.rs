// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026
//
// Author: Vasant Karasulli <vkarasulli@suse.de>
//

extern crate alloc;

use crate::error::SvsmError;
use crate::fs::*;
use crate::locking::SpinLock;
use crate::syscall::Obj;
use alloc::string::String;
use alloc::sync::Arc;
pub fn initialize_log_buffer() -> Result<usize, SvsmError> {
    mkdir("Log").map_err(|_| SvsmError::LogError)?;
    let _handle = create("Log/logfile").map_err(|_| SvsmError::LogError)?;
    Ok(0)
}

pub fn log_write(buf: &[u8]) -> Result<usize, SvsmError> {
    let handle = open_write("Log/logfile").map_err(|_| SvsmError::LogError)?;
    handle.seek_end(0);
    handle.write(buf).map_err(|_| SvsmError::LogError)
}

pub fn log_read(buf: &mut [u8]) -> Result<usize, SvsmError> {
    let handle = open_read("Log/logfile").map_err(|_| SvsmError::LogError)?;
    handle.read(buf).map_err(|_| SvsmError::LogError)
}

#[cfg(all(test, test_in_svsm))]
pub fn log_reset() -> Result<usize, SvsmError> {
    let handle = open_write("Log/logfile").map_err(|_| SvsmError::LogError)?;
    handle.truncate(0).map_err(|_| SvsmError::LogError)
}

#[derive(Debug)]
struct LogBuffer {
    lb: SpinLock<StdoutBuffer>,
}

impl LogBuffer {
    fn new(component: String) -> Self {
        Self {
            lb: SpinLock::new(StdoutBuffer::new(component)),
        }
    }
}

impl File for LogBuffer {
    fn read(&self, _buf: &mut [u8], _offset: usize) -> Result<usize, SvsmError> {
        Err(SvsmError::FileSystem(FsError::not_supported()))
    }

    fn read_buffer(&self, _buffer: &mut dyn Buffer, _offset: usize) -> Result<usize, SvsmError> {
        Err(SvsmError::FileSystem(FsError::not_supported()))
    }

    fn write(&self, buf: &[u8], _offset: usize) -> Result<usize, SvsmError> {
        self.lb.lock().stdout_write(buf, true)
    }

    fn write_buffer(&self, buffer: &dyn Buffer, _offset: usize) -> Result<usize, SvsmError> {
        self.lb.lock().stdout_write_buffer(buffer, true)
    }

    fn truncate(&self, _size: usize) -> Result<usize, SvsmError> {
        Err(SvsmError::FileSystem(FsError::not_supported()))
    }

    fn size(&self) -> usize {
        0
    }
}

pub fn stdout_open(taskname: String) -> (Arc<dyn Obj>, Arc<dyn Obj>) {
    let console_file: Arc<dyn File> = Arc::new(ConsoleFile::new(taskname.clone()));
    let log_file: Arc<dyn File> = Arc::new(LogBuffer::new(taskname.clone()));

    // Stdout is write-only.
    (
        Arc::new(FsObj::new_file(FileHandle::new(&console_file, false, true))),
        Arc::new(FsObj::new_file(FileHandle::new(&log_file, false, true))),
    )
}
