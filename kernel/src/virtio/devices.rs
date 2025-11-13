// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Oliver Steffen <osteffen@redhat.com>
// Author: Stefano Garzarella <sgarzare@redhat.com>

use super::hal::*;
extern crate alloc;
use alloc::boxed::Box;
use core::ops::DerefMut;
use core::ptr::NonNull;
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::device::socket::{VirtIOSocket, VsockConnectionManager};
use virtio_drivers::transport::mmio::{MmioError, MmioTransport};
use virtio_drivers::transport::{DeviceType, Transport};
use virtio_drivers::PAGE_SIZE;

use super::error::*;
use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::fw_cfg::FwCfg;
use crate::locking::{RWLock, SpinLock};
use crate::mm::global_memory::{map_global_range_4k_shared, GlobalRangeGuard};
use crate::mm::pagetable::PTEntryFlags;
use crate::platform::SVSM_PLATFORM;
use alloc::vec::Vec;

#[derive(Debug)]
pub struct MMIOSlot {
    pub free: bool,
    pub addr: PhysAddr,
}

pub static MMIO_SLOTS: RWLock<Option<Vec<MMIOSlot>>> = RWLock::new(None);

pub fn virtio_mmio_init() {
    let cfg: FwCfg<'_> = FwCfg::new(SVSM_PLATFORM.get_io_port());

    let driver = cfg
        .get_virtio_mmio_addresses()
        .expect("No MMIO slots found");

    let mut mmio_slots_vec: Vec<MMIOSlot> = Vec::new();

    driver.iter().for_each(|address| {
        let entry = MMIOSlot {
            free: true,
            addr: PhysAddr::from(*address),
        };
        mmio_slots_vec.push(entry);
    });

    *MMIO_SLOTS.lock_write().deref_mut() = Some(mmio_slots_vec);
}

pub struct VirtIOBlkDevice {
    pub device: SpinLock<VirtIOBlk<SvsmHal, MmioTransport<SvsmHal>>>,
    _mmio_space: GlobalRangeGuard,
    phys_addr: PhysAddr,
}

impl core::fmt::Debug for VirtIOBlkDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtIOBlkDevice").finish()
    }
}

impl VirtIOBlkDevice {
    pub fn new(slot: &mut MMIOSlot) -> Result<Box<Self>, SvsmError> {
        virtio_init();

        let mem = map_global_range_4k_shared(slot.addr, PAGE_SIZE, PTEntryFlags::data())?;

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

        slot.free = false;

        Ok(Box::new(VirtIOBlkDevice {
            device: SpinLock::new(blk),
            _mmio_space: mem,
            phys_addr: slot.addr,
        }))
    }
}

impl Drop for VirtIOBlkDevice {
    fn drop(&mut self) {
        let mut binding = MMIO_SLOTS.lock_write();
        let slots = binding.as_mut().unwrap();

        let slot = slots
            .iter_mut()
            .find(|slot| slot.addr == self.phys_addr)
            .unwrap();
        slot.free = true;
    }
}

pub struct VirtIOVsockDevice {
    pub device: SpinLock<VsockConnectionManager<SvsmHal, MmioTransport<SvsmHal>>>,
    _mmio_space: GlobalRangeGuard,
    phys_addr: PhysAddr,
}

impl core::fmt::Debug for VirtIOVsockDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtIOVsockDevice").finish()
    }
}

impl VirtIOVsockDevice {
    pub fn new(slot: &mut MMIOSlot) -> Result<Box<Self>, SvsmError> {
        virtio_init();

        let mem = map_global_range_4k_shared(slot.addr, PAGE_SIZE, PTEntryFlags::data())?;

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

        if transport.device_type() != DeviceType::Socket {
            return Err(VirtioError::InvalidDeviceType)?;
        }

        let vsk = VirtIOSocket::new(transport).map_err(|_| VirtioError::InvalidDevice)?;
        let mgr = VsockConnectionManager::new(vsk);

        slot.free = false;

        Ok(Box::new(VirtIOVsockDevice {
            device: SpinLock::new(mgr),
            _mmio_space: mem,
            phys_addr: slot.addr,
        }))
    }
}

impl Drop for VirtIOVsockDevice {
    fn drop(&mut self) {
        let mut binding = MMIO_SLOTS.lock_write();
        let slots = binding.as_mut().unwrap();

        let slot = slots
            .iter_mut()
            .find(|slot| slot.addr == self.phys_addr)
            .unwrap();
        slot.free = true;
    }
}
