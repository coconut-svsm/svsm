// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::{write, FsObjHandle, ObjHandle, SysCallError};

static CONSOLE_HANDLE: FsObjHandle = FsObjHandle::new(ObjHandle::new(0));

pub fn write_console(buf: &[u8]) -> Result<usize, SysCallError> {
    write(&CONSOLE_HANDLE, buf)
}
