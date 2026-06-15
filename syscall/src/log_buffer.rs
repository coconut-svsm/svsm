// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

use crate::{FsObjHandle, ObjHandle, SysCallError, write};

static LOG_HANDLE: FsObjHandle = FsObjHandle::new(ObjHandle::new(1));
#[cfg(feature = "enable-console-log")]
static CONSOLE_HANDLE: FsObjHandle = FsObjHandle::new(ObjHandle::new(0));

pub fn write_log(buf: &[u8]) -> Result<usize, SysCallError> {
    write(&LOG_HANDLE, buf)?;
    #[cfg(feature = "enable-console-log")]
    write(&CONSOLE_HANDLE, buf)?;
    Ok(0)
}
