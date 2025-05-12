// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc.
//
// Author: Oliver Steffen <osteffen@redhat.com>

pub mod api;
pub mod error;
#[cfg(feature = "virtio-drivers")]
pub mod virtio_blk;

pub use error::BlockDeviceError;
