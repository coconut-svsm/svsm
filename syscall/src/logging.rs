// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

use crate::{FsObjHandle, ObjHandle, STDOUT_FILENO, SysCallError, write};

/// Standard output, which is the log. The kernel attaches it to the file
/// descriptor 1 of every task.
static LOG_HANDLE: FsObjHandle = FsObjHandle::new(ObjHandle::new(STDOUT_FILENO));

pub fn write_log(buf: &[u8]) -> Result<usize, SysCallError> {
    write(&LOG_HANDLE, buf)
}
