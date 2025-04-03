// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Oliver Steffen <osteffen@redhat.com>

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VirtioError {
    /// No valid VirtIO device found the specified address. This can be due to
    /// a bad magic number, an unsupported VirtIO version, or a zeroed device ID.
    InvalidDevice,
    /// The supplied VirtIO device is not of the extpected type.
    /// This is returned, for example, when a blk device driver is given the MMIO address of a vsock device.
    InvalidDeviceType,
}
