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

#[cfg(all(test, test_in_svsm))]
mod tests {
    use crate::{
        address::PhysAddr, fw_cfg::FwCfg, platform::SVSM_PLATFORM, testutils::is_qemu_test_env,
    };
    use core::cmp::min;
    extern crate alloc;
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

    /// Get the sha256 sum of the disk image from the host (see `scripts/test-in-svsm.sh`)
    fn get_image_hash_from_host() -> Option<[u8; 32]> {
        use crate::serial::Terminal;
        use crate::testing::{svsm_test_io, IORequest};

        let sp = svsm_test_io().unwrap();

        sp.put_byte(IORequest::GetStateImageSha256 as u8);

        let mut expected_measurement = [0u8; 32];
        for byte in &mut expected_measurement {
            *byte = sp.get_byte();
        }

        Some(expected_measurement)
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_read_4sectors() {
        if is_qemu_test_env() {
            virtio_read(4);
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_read_8sectors() {
        if is_qemu_test_env() {
            virtio_read(8);
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_read_9sectors() {
        if is_qemu_test_env() {
            virtio_read(9);
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_read_17sectors() {
        if is_qemu_test_env() {
            virtio_read(17);
        }
    }

    /// Read from the block device using the specified buffer size for earch
    /// request. Then verify the data was correctly read by comparing the sha256
    /// sums of the read data and the image as seen on the host.
    fn virtio_read(sectors_at_once: usize) {
        use alloc::vec;
        use sha2::{Digest, Sha256};
        assert!(sectors_at_once > 0);
        let blk = get_blk_device();

        let expected_hash = get_image_hash_from_host().unwrap();

        let n_sectors = blk.size() / SECTOR_SIZE;
        let mut buffer = vec![0u8; sectors_at_once * SECTOR_SIZE];

        let mut hasher = Sha256::new();
        for (pos, sectors) in (0..n_sectors)
            .step_by(sectors_at_once)
            .map(|pos| (pos, min(sectors_at_once, n_sectors - pos)))
        {
            buffer.truncate(sectors * SECTOR_SIZE);

            blk.read_blocks(pos, &mut buffer).unwrap();
            hasher.update(&buffer);
        }

        let hash = hasher.finalize();
        assert_eq!(expected_hash, *hash);
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_write_4sectors() {
        if is_qemu_test_env() {
            virtio_write(4);
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_write_8sectors() {
        if is_qemu_test_env() {
            virtio_write(8);
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_write_9sectors() {
        if is_qemu_test_env() {
            virtio_write(9);
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_write_17sectors() {
        if is_qemu_test_env() {
            virtio_write(17);
        }
    }

    /// Write to the block device and fill it with (random) data, writing with the
    /// specified buffer size each time. Then verify the data correctly reached the
    /// disk image by comparing the sha256 sums of the witten data and the image as seen
    /// on the host.
    fn virtio_write(sectors_at_once: usize) {
        use alloc::vec;
        use sha2::{Digest, Sha256};

        assert!(sectors_at_once > 0);

        let blk = get_blk_device();

        let n_sectors = blk.size() / SECTOR_SIZE;
        let mut buffer = vec![0u8; sectors_at_once * SECTOR_SIZE];

        let mut hasher = Sha256::new();

        let mut gen = (0u64..).flat_map(|x| x.to_le_bytes());

        for (pos, sectors) in (0..n_sectors)
            .step_by(sectors_at_once)
            .map(|pos| (pos, min(sectors_at_once, n_sectors - pos)))
        {
            buffer.truncate(sectors * SECTOR_SIZE);

            buffer.fill_with(|| gen.next().unwrap());

            blk.write_blocks(pos, &buffer).unwrap();
            blk.flush().unwrap();
            hasher.update(&buffer);
        }

        let hash = hasher.finalize();
        let expected_hash = get_image_hash_from_host().unwrap();

        assert_eq!(expected_hash, *hash);
    }
}
