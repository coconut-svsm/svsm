// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Oliver Steffen <osteffen@redhat.com>
// Author: Stefano Garzarella <sgarzare@redhat.com>

use core::sync::atomic::AtomicU32;

use super::hal::*;
extern crate alloc;
use alloc::boxed::Box;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::device::socket::{VirtIOSocket, VsockConnectionManager};
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
    pub fn new(slot: MmioSlot) -> Result<Box<Self>, SvsmError> {
        let blk = VirtIOBlk::new(slot.transport).map_err(|_| VirtioError::InvalidDevice)?;

        Ok(Box::new(VirtIOBlkDevice {
            device: SpinLock::new(blk),
            _mmio_space: slot.mmio_range,
        }))
    }
}

pub struct VirtIOVsockDevice {
    pub device: SpinLock<VsockConnectionManager<SvsmHal, MmioTransport<SvsmHal>>>,
    pub first_free_port: AtomicU32,
    _mmio_space: GlobalRangeGuard,
}

impl core::fmt::Debug for VirtIOVsockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtIOVsockDevice").finish()
    }
}

impl VirtIOVsockDevice {
    pub fn new(slot: MmioSlot) -> Result<Box<Self>, SvsmError> {
        let vsk = VirtIOSocket::new(slot.transport).map_err(|_| VirtioError::InvalidDevice)?;
        let mgr = VsockConnectionManager::new(vsk);

        Ok(Box::new(VirtIOVsockDevice {
            device: SpinLock::new(mgr),
            first_free_port: AtomicU32::new(1024),
            _mmio_space: slot.mmio_range,
        }))
    }
}
