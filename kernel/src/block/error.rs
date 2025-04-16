// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Oliver Steffen <osteffen@redhat.com>

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlockDeviceError {
    /// Generic error for all read and write operations on a block device.
    Failed,
}
