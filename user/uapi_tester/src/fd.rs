// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Advanced Micro Devices, Inc
//
// Author: Mahmoud Nagy Adam <madam@amd.com>

//! Tests for the file descriptors of a task.

use super::sys::{sys1, sys3};
use userlib::{
    FileFlags, FileModes, Obj, SYS_CLOSE, SYS_READ, SYS_WRITE, SysCallError, open, unlink,
};

/// Checks that standard output and standard error, the file descriptors 1 and
/// 2, are the log and accept writes, and that standard input, the file
/// descriptor 0, is open, always at the end and not writable.
#[test]
#[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
fn test_log_descriptors() {
    let msg = b"test_log_descriptors\n";

    for fd in [1, 2] {
        let ret = sys3(SYS_WRITE, fd, msg.as_ptr() as u64, msg.len() as u64).unwrap();
        assert_eq!(ret, msg.len() as u64);
    }

    let ret = sys3(SYS_WRITE, 0, msg.as_ptr() as u64, msg.len() as u64);
    assert_eq!(ret, Err(SysCallError::EBADF));

    let mut buf = [0u8; 8];
    let ret = sys3(SYS_READ, 0, buf.as_mut_ptr() as u64, buf.len() as u64);
    assert_eq!(ret, Ok(0));
}

/// Checks that closing a file descriptor that is not open fails with EBADF
#[test]
#[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
fn test_close_bad_descriptor() {
    let bad = sys1(SYS_CLOSE, 1000);
    assert_eq!(bad, Err(SysCallError::EBADF));

    let path = c"/test_close_bad_descriptor";
    let file = open(path, FileModes::WRITE, FileFlags::CREATE).unwrap();
    let fd = u64::from(file.id());
    // Dropping the handle closes the file descriptor.
    drop(file);
    let again = sys1(SYS_CLOSE, fd);
    assert_eq!(again, Err(SysCallError::EBADF));

    unlink(path).unwrap();
}
