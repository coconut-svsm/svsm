// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
//
use crate::address::VirtAddr;
use crate::locking::SpinLock;
use crate::log_buffer::LogBuffer;

// struct containing information that
// is migrated from stage2 to svsm kernel
#[repr(C)]
pub struct MigrateInfo {
    pub bitmap_addr: VirtAddr,
    pub log_buf: &'static SpinLock<LogBuffer>,
}

impl MigrateInfo {
    pub fn new(vb: VirtAddr, lb: &'static SpinLock<LogBuffer>) -> Self {
        MigrateInfo {
            bitmap_addr: vb,
            log_buf: lb,
        }
    }
}
