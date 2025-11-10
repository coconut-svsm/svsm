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
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use virtio_drivers::device::blk::VirtIOBlk;
use virtio_drivers::transport::mmio::{MmioError, MmioTransport};
use virtio_drivers::transport::{DeviceType, Transport};
use virtio_drivers::PAGE_SIZE;

use super::error::*;
use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::fw_cfg::FwCfg;
use crate::locking::SpinLock;
use crate::mm::global_memory::{map_global_range_4k_shared, GlobalRangeGuard};
use crate::mm::pagetable::PTEntryFlags;
use crate::platform::SVSM_PLATFORM;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use alloc::vec::Vec;

#[derive(Debug)]
pub struct MMIOSlot {
    free: AtomicBool,
    addr: PhysAddr,
}

impl MMIOSlot {
    pub fn new(addr: PhysAddr) -> Self {
        Self {
            free: AtomicBool::new(true),
            addr,
        }
    }

    pub fn try_acquire(&self) -> Option<MMIOSlotGuard> {
        self.free
            .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
            .ok()
            .map(|_| MMIOSlotGuard { addr: self.addr })
    }
}

#[derive(Debug)]
pub struct MMIOSlotGuard {
    addr: PhysAddr,
}

impl Drop for MMIOSlotGuard {
    fn drop(&mut self) {
        let Ok(slots) = MMIO_SLOTS.try_get_inner() else {
            log::warn!("MMIO Slots not initialized");
            return;
        };

        if let Some(slot) = slots.iter().find(|x| x.addr == self.addr) {
            slot.free.store(true, Ordering::Relaxed)
        }
    }
}

pub static MMIO_SLOTS: ImmutAfterInitCell<Vec<MMIOSlot>> = ImmutAfterInitCell::uninit();

pub fn virtio_mmio_init() {
    let cfg: FwCfg<'_> = FwCfg::new(SVSM_PLATFORM.get_io_port());

    let Ok(addresses) = cfg.get_virtio_mmio_addresses() else {
        log::warn!("No MMIO slots found");
        return;
    };

    let mut mmio_slots_vec: Vec<MMIOSlot> = Vec::new();

    addresses.iter().for_each(|address| {
        let entry = MMIOSlot::new(PhysAddr::from(*address));
        mmio_slots_vec.push(entry);
    });

    MMIO_SLOTS
        .init(mmio_slots_vec)
        .expect("MMIO Slots already initialized");
}

pub struct VirtIOBlkDevice {
    pub device: SpinLock<VirtIOBlk<SvsmHal, MmioTransport<SvsmHal>>>,
    _mmio_space: GlobalRangeGuard,
    _slot: MMIOSlotGuard,
}

impl core::fmt::Debug for VirtIOBlkDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtIOBlkDevice").finish()
    }
}

impl VirtIOBlkDevice {
    pub fn new(slot: MMIOSlotGuard) -> Result<Box<Self>, SvsmError> {
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

        Ok(Box::new(VirtIOBlkDevice {
            device: SpinLock::new(blk),
            _mmio_space: mem,
            _slot: slot,
        }))
    }
}
