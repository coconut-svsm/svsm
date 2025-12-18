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

extern crate alloc;
use crate::{block::api::BlockDriver, utils::immut_after_init::ImmutAfterInitCell};
use alloc::boxed::Box;

// Currently only one block device is supported.
static BLOCK_DEVICE: ImmutAfterInitCell<Box<dyn BlockDriver>> = ImmutAfterInitCell::uninit();
