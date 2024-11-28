// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc.
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Oliver Steffen <osteffen@redhat.com>

use super::api::{BlockDeviceError, BlockDriver};
use crate::address::PhysAddr;
use crate::virtio::devices::VirtIOBlkDevice;
use virtio_drivers::device::blk::SECTOR_SIZE;

pub struct VirtIOBlkDriver(VirtIOBlkDevice);

impl core::fmt::Debug for VirtIOBlkDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtIOBlkDriver").finish()
    }
}

impl VirtIOBlkDriver {
    pub fn new(mmio_base: PhysAddr) -> Self {
        VirtIOBlkDriver(VirtIOBlkDevice::new(mmio_base))
    }
}

impl BlockDriver for VirtIOBlkDriver {
    fn read_blocks(&self, block_id: usize, buf: &mut [u8]) -> Result<(), BlockDeviceError> {
        self.0
            .device
            .lock()
            .read_blocks(block_id, buf)
            .map_err(|_| BlockDeviceError::Failed)
    }

    fn write_blocks(&self, block_id: usize, buf: &[u8]) -> Result<(), BlockDeviceError> {
        self.0
            .device
            .lock()
            .write_blocks(block_id, buf)
            .map_err(|_| BlockDeviceError::Failed)
    }

    fn block_size_log2(&self) -> u8 {
        SECTOR_SIZE.ilog2().try_into().unwrap()
    }

    fn size(&self) -> usize {
        self.0.device.lock().capacity() as usize * SECTOR_SIZE
    }
}
