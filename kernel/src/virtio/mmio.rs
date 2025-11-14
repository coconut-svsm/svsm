// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Luigi Leonardi <leonardi@redhat.com>

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::NonNull;

use virtio_drivers::transport::{DeviceType, Transport, mmio::MmioTransport};

use crate::address::PhysAddr;
use crate::fw_cfg::FwCfg;
use crate::igvm_params::IgvmParams;
use crate::mm::{GlobalRangeGuard, map_global_range_4k_shared, pagetable::PTEntryFlags};
use crate::platform::SVSM_PLATFORM;
use crate::types::PAGE_SIZE;
use crate::virtio::hal::{SvsmHal, virtio_init};

#[derive(Debug)]
pub struct MmioSlot {
    pub mmio_range: GlobalRangeGuard,
    pub transport: MmioTransport<SvsmHal>,
}

#[derive(Debug, Default)]
pub struct MmioSlots {
    slots: Vec<MmioSlot>,
}

/// Probes and enumerates all virtio-MMIO devices available in the system.
///
/// This function queries the fw_cfg interface to discover virtio-MMIO device
/// addresses and maps their MMIO regions.
///
/// # Usage
///
/// This function is typically called once during early system initialization
/// to discover all available virtio devices. Each slot in the returned collection
/// should be consumed exactly once by calling [`MmioSlots::pop_slot`], as each
/// slot represents exclusive ownership of a device's MMIO region.
///
/// # Returns
///
/// Returns an [`MmioSlots`] collection containing all discovered virtio-MMIO devices.
/// Returns an empty collection if no devices are found or if the fw_cfg interface
/// is unavailable.
pub fn probe_mmio_slots(igvm_params: &IgvmParams<'_>) -> MmioSlots {
    // Virtio MMIO addresses are discovered via fw_cfg, so skip probing
    // if it is not present.
    if !igvm_params.has_fw_cfg_port() {
        return MmioSlots::default();
    }

    virtio_init();

    let cfg = FwCfg::new(SVSM_PLATFORM.get_io_port());
    let Ok(dev) = cfg.get_virtio_mmio_addresses() else {
        return MmioSlots::default();
    };

    let mut slots = Vec::with_capacity(dev.len());

    for addr in dev {
        let phys_addr = PhysAddr::from(addr);

        let Ok(mem) = map_global_range_4k_shared(phys_addr, PAGE_SIZE, PTEntryFlags::data()) else {
            log::warn!("MmioSlots: Failed to map MMIO region at {:x}", addr);
            continue;
        };

        // Not expected to fail, because mem exists.
        let header = NonNull::new(mem.addr().as_mut_ptr()).unwrap();

        // SAFETY: `map_global_range_4k_shared` guarantees us proper address alignment.
        // The memory region has the same lifetime of the MmioSlot structure which will be consumed by the driver.
        let Ok(transport) = (unsafe { MmioTransport::<SvsmHal>::new(header) }) else {
            // Currently QEMU advertises _all_ slots, regardless they are empty or not.
            log::debug!("MmioSlots: {:x} empty", addr);
            continue;
        };

        log::info!(
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

    MmioSlots { slots }
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
        let pos = self
            .slots
            .iter()
            .position(|slot| slot.transport.device_type() == virtio_type)?;
        Some(self.slots.remove(pos))
    }
}
