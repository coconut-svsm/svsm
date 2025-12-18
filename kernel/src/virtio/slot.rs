// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Luigi Leonardi <leonardi@redhat.com>

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::NonNull;

use virtio_drivers::transport::{mmio::MmioTransport, DeviceType, Transport};

use crate::{
    address::PhysAddr,
    fw_cfg::FwCfg,
    mm::{map_global_range_4k_shared, pagetable::PTEntryFlags, GlobalRangeGuard},
    platform::SVSM_PLATFORM,
    types::PAGE_SIZE,
    virtio::hal::{virtio_init, SvsmHal},
};

#[derive(Debug)]
pub struct MmioSlot {
    pub mmio_range: GlobalRangeGuard,
    pub transport: MmioTransport<SvsmHal>,
}

#[derive(Debug)]
pub struct MmioSlots {
    slots: Vec<MmioSlot>,
}

/// Probes and enumerates all virtio-MMIO devices available in the system.
///
/// This function queries the fw_cfg interface to discover virtio-MMIO device
/// addresses and maps their MMIO regions.
///
/// # Returns
///
/// * `Some(MmioSlots)` - Collection of discovered VirtIO devices
/// * `None` - No virtio-MMIO devices found
///
/// # Safety
///
/// Must be called on the bootstrap processor (BSP) before other CPUs are started.
/// This function is not thread-safe and performs global device enumeration that
/// must only happen once during system initialization.
///
/// The caller must ensure:
/// * Single-threaded execution
/// * Called exactly once during boot
pub unsafe fn probe_mmio_slots() -> Option<MmioSlots> {
    virtio_init();

    let cfg = FwCfg::new(SVSM_PLATFORM.get_io_port());
    let dev = cfg.get_virtio_mmio_addresses().ok()?;
    let mut slots = Vec::with_capacity(dev.len());

    for addr in dev {
        let phys_addr = PhysAddr::from(addr);

        let Ok(mem) = map_global_range_4k_shared(phys_addr, PAGE_SIZE, PTEntryFlags::data()) else {
            log::warn!("MmioSlots: Failed to map MMIO region at {:x}", addr);
            continue;
        };

        // Not expected to fail, because mem exists.
        let header = NonNull::new(mem.addr().as_mut_ptr()).unwrap();

        // SAFETY: `header` is the MMIO config area; we have to trust the content is valid.
        let Ok(transport) = (unsafe { MmioTransport::<SvsmHal>::new(header) }) else {
            log::debug!("MmioSlots: {:x} empty", addr);
            continue;
        };

        log::debug!(
            "MmioSlots: Found {:?} at {:x}",
            transport.device_type(),
            addr
        );

        let slot_type = MmioSlot {
            mmio_range: mem,
            transport,
        };

        slots.push(slot_type);
    }

    Some(MmioSlots { slots })
}

impl MmioSlots {
    /// Retrieves and removes the first available MMIO slot matching the specified device type.
    ///
    /// This method consumes the slot. Once retrieved, the slot is removed
    /// from the array and cannot be obtained again. This ensures each
    /// virtio device is initialized exactly once and forbids driver unloading.
    ///
    /// # Arguments
    ///
    /// * `virtio_type` - The virtio device type to search for
    ///
    /// # Returns
    ///
    /// * `Some(MmioSlot)` - The first matching slot
    /// * `None` - No slot matching the requested device type was found
    pub fn pop_slot(&mut self, virtio_type: DeviceType) -> Option<MmioSlot> {
        self.slots
            .pop_if(|slot| slot.transport.device_type() == virtio_type)
    }
}
