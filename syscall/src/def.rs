// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

// Syscall classes
const CLASS0: u64 = 0;

// Syscall number in class0
pub const SYS_EXIT: u64 = CLASS0;
pub const SYS_CLOSE: u64 = CLASS0 + 10;
