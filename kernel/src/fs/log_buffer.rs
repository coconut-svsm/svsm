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

#[cfg(all(test, test_in_svsm))]
mod tests {
    use super::*;
    use crate::task::{KernelThreadStartInfo, start_kernel_task};

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_log_buffer_basic() {
        let _ = log_reset();
        log::info!("hello world");
        let mut buf1 = [0u8; 29];
        let _ = log_read(&mut buf1);
        assert_eq!(
            str::from_utf8(&buf1).unwrap(),
            "[SVSM test task] hello world\n"
        );
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_log_buffer_multiple_tasks() {
        let _ = log_reset();
        log::info!("in test task");
        start_kernel_task(KernelThreadStartInfo::new(task1, 1), String::from("task1"))
            .expect("Failed to launch request processing task");
        start_kernel_task(KernelThreadStartInfo::new(task2, 2), String::from("task2"))
            .expect("Failed to launch request processing task");
        let expected = "[SVSM test task] in test task\n[task1] in task1\n[task2] in task2\n";
        let mut buf1 = [0u8; 64];
        let _ = log_read(&mut buf1);
        assert_eq!(str::from_utf8(&buf1).unwrap(), expected);
    }

    fn task1(start_parameter: usize) {
        assert_eq!(start_parameter, 1);
        log::info!("in task1");
    }

    fn task2(start_parameter: usize) {
        assert_eq!(start_parameter, 2);
        log::info!("in task2");
    }
}
