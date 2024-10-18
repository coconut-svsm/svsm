// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>
use crate::address::VirtAddr;
use crate::locking::SpinLock;
use crate::log_buffer::LogBuffer;

// struct containing information that
// is migrated from stage2 to svsm kernel
#[derive(Copy, Clone, Debug)]
pub struct MigrateInfo {
    pub bitmap_addr: VirtAddr,
    pub lb: &'static SpinLock<LogBuffer>,
}

impl MigrateInfo {
    pub fn new(vb: VirtAddr, lb: &'static SpinLock<LogBuffer>) -> Self {
        MigrateInfo {
            bitmap_addr: vb,
            lb,
        }
    }
}
