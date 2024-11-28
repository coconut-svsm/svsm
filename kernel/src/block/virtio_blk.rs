// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc.
//
// Author: Stefano Garzarella <sgarzare@redhat.com>
// Author: Oliver Steffen <osteffen@redhat.com>

use super::api::BlockDriver;
use crate::address::PhysAddr;
use crate::block::BlockDeviceError;
use crate::error::SvsmError;
use crate::types::PAGE_SIZE;
use crate::virtio::devices::VirtIOBlkDevice;
use virtio_drivers::device::blk::SECTOR_SIZE;
extern crate alloc;
use alloc::boxed::Box;
pub struct VirtIOBlkDriver(Box<VirtIOBlkDevice>);

impl core::fmt::Debug for VirtIOBlkDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtIOBlkDriver").finish()
    }
}

impl VirtIOBlkDriver {
    pub fn new(mmio_base: PhysAddr) -> Result<Self, SvsmError> {
        Ok(VirtIOBlkDriver(VirtIOBlkDevice::new(mmio_base)?))
    }
}

impl BlockDriver for VirtIOBlkDriver {
    fn read_blocks(&self, block_id: usize, buf: &mut [u8]) -> Result<(), SvsmError> {
        self.0.device.locked_do(|dev| {
            buf.chunks_mut(PAGE_SIZE)
                .zip((block_id..).step_by(PAGE_SIZE / SECTOR_SIZE))
                .try_for_each(|(chunk, pos)| {
                    dev.read_blocks(pos, chunk)
                        .map_err(|_| SvsmError::Block(BlockDeviceError::Failed))
                })
        })
    }

    fn write_blocks(&self, block_id: usize, buf: &[u8]) -> Result<(), SvsmError> {
        self.0.device.locked_do(|dev| {
            buf.chunks(PAGE_SIZE)
                .zip((block_id..).step_by(PAGE_SIZE / SECTOR_SIZE))
                .try_for_each(|(chunk, pos)| {
                    dev.write_blocks(pos, chunk)
                        .map_err(|_| SvsmError::Block(BlockDeviceError::Failed))
                })
        })
    }

    fn block_size_log2(&self) -> u8 {
        SECTOR_SIZE.ilog2().try_into().unwrap()
    }

    fn size(&self) -> usize {
        self.0.device.lock().capacity() as usize * SECTOR_SIZE
    }

    fn flush(&self) -> Result<(), SvsmError> {
        self.0
            .device
            .lock()
            .flush()
            .map_err(|_| SvsmError::Block(BlockDeviceError::Failed))
    }
}
