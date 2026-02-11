// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Oliver Steffen <osteffen@redhat.com>
// Author: Stefano Garzarella <sgarzare@redhat.com>

use super::hal::*;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::MmioTransport;

use super::error::*;
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::global_memory::GlobalRangeGuard;
use crate::virtio::mmio::MmioSlot;

pub struct VirtIOBlkDevice {
    pub device: SpinLock<VirtIOBlk<SvsmHal, MmioTransport<SvsmHal>>>,
    _mmio_space: GlobalRangeGuard,
}

impl core::fmt::Debug for VirtIOBlkDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtIOBlkDevice").finish()
    }
}

impl VirtIOBlkDevice {
    pub fn new(slot: MmioSlot) -> Result<Self, SvsmError> {
        let blk = VirtIOBlk::new(slot.transport).map_err(|_| VirtioError::InvalidDevice)?;

        Ok(VirtIOBlkDevice {
            device: SpinLock::new(blk),
            _mmio_space: slot.mmio_range,
        })
    }
}
