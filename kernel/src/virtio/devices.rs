// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Oliver Steffen <osteffen@redhat.com>
// Author: Stefano Garzarella <sgarzare@redhat.com>

use super::hal::*;
extern crate alloc;
use alloc::boxed::Box;
use core::ptr::NonNull;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::{MmioError, MmioTransport};
use virtio_drivers::transport::{DeviceType, Transport};
use virtio_drivers::PAGE_SIZE;

use super::error::*;
use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::global_memory::{map_global_range_4k_shared, GlobalRangeGuard};
use crate::mm::pagetable::PTEntryFlags;

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
    pub fn new(mmio_base: PhysAddr) -> Result<Box<Self>, SvsmError> {
        virtio_init();

        let mem = map_global_range_4k_shared(mmio_base, PAGE_SIZE, PTEntryFlags::data())?;

        // Not expected to fail, because mem exists.
        let header = NonNull::new(mem.addr().as_mut_ptr()).unwrap();

        // SAFETY: `header` is the MMIO config area; we have to trust the content is valid.
        let transport = unsafe {
            // TODO: Use more detailed error types ?
            MmioTransport::<SvsmHal>::new(header).map_err(|e| match e {
                MmioError::BadMagic(_) => VirtioError::InvalidDevice,
                MmioError::UnsupportedVersion(_) => VirtioError::InvalidDevice,
                MmioError::ZeroDeviceId => VirtioError::InvalidDevice,
            })?
        };

        if transport.device_type() != DeviceType::Block {
            return Err(VirtioError::InvalidDeviceType)?;
        }

        let blk = VirtIOBlk::new(transport).map_err(|_| VirtioError::InvalidDevice)?;

        Ok(Box::new(VirtIOBlkDevice {
            device: SpinLock::new(blk),
            _mmio_space: mem,
        }))
    }
}
