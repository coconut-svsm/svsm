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
        self.0
            .device
            .lock()
            .read_blocks(block_id, buf)
            .map_err(|_| SvsmError::Block(BlockDeviceError::Failed))
    }

    fn write_blocks(&self, block_id: usize, buf: &[u8]) -> Result<(), SvsmError> {
        self.0
            .device
            .lock()
            .write_blocks(block_id, buf)
            .map_err(|_| SvsmError::Block(BlockDeviceError::Failed))
    }

    fn block_size_log2(&self) -> u8 {
        SECTOR_SIZE.ilog2().try_into().unwrap()
    }

    fn size(&self) -> usize {
        self.0.device.lock().capacity() as usize * SECTOR_SIZE
    }
}

#[cfg(test)]
mod tests {
    use crate::{address::PhysAddr, fw_cfg::FwCfg, platform::SVSM_PLATFORM};
    extern crate alloc;
    use alloc::vec::Vec;
    use zerocopy::IntoBytes;

    use super::*;

    /// Find the first virtio-blk device in the hardware-info list
    fn get_blk_device() -> VirtIOBlkDriver {
        let cfg = FwCfg::new(SVSM_PLATFORM.get_io_port());

        let dev = cfg
            .get_virtio_mmio_addresses()
            .unwrap_or_default()
            .iter()
            .find_map(|a| VirtIOBlkDriver::new(PhysAddr::from(*a)).ok())
            .expect("No virtio-blk device found");

        dev
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    pub fn test_virtio_blk_512() {
        let drv = get_blk_device();
        readback_test(&drv, 512);
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    pub fn test_virtio_blk_4096() {
        let drv = get_blk_device();
        readback_test(&drv, 4096);
    }

    fn readback_test(blk: &VirtIOBlkDriver, block_size: usize) {
        for l in [[0xaa, 0x55], [0x55, 0xaa]] {
            let mut buf: Vec<u8> = core::iter::repeat(l).flatten().take(block_size).collect();
            let blocks = blk.size() / block_size;

            for i in 0..blocks {
                buf[0..size_of::<usize>()].copy_from_slice(usize::as_bytes(&i));
                blk.write_blocks(i * (block_size / SECTOR_SIZE), &buf)
                    .unwrap();
            }

            let mut rbuf: Vec<u8> = alloc::vec![0; block_size];

            for i in 0..blocks {
                buf[0..size_of::<usize>()].copy_from_slice(usize::as_bytes(&i));
                blk.read_blocks(i * (block_size / SECTOR_SIZE), &mut rbuf)
                    .unwrap();
                assert!(rbuf == buf, "Error in block {i}: {rbuf:x?} != {buf:x?}");
            }
        }
    }
}
