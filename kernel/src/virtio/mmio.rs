// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Luigi Leonardi <leonardi@redhat.com>

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::NonNull;

use virtio_drivers::transport::mmio::VirtIOHeader;
use virtio_drivers::transport::{DeviceType, Transport, mmio::MmioTransport};

use crate::address::{Address, PhysAddr};
use crate::boot_params::BootParams;
use crate::fw_cfg::FwCfg;
use crate::mm::{GlobalRangeGuard, map_global_range_4k_shared, pagetable::PTEntryFlags};
use crate::platform::SVSM_PLATFORM;
use crate::types::PAGE_SIZE;
use crate::virtio::hal::virtio_init;

#[derive(Debug)]
pub struct MmioSlot {
    pub transport: MmioTransport<'static>,
    // Fields are ordered so that `mmio_range` is dropped last.
    // The MmioTransport destructor resets the device via MMIO writes, and
    // dropping `mmio_range` destroys the mapping, so `mmio_range` must be
    // dropped last.
    // This drop-order behavior is stable.
    // See https://doc.rust-lang.org/reference/destructors.html
    //
    // TODO: The destruction order should be expressed via code rather than
    // relying on field ordering. This should be addressed when moving to
    // the upstream virtio-drivers crate.
    pub mmio_range: GlobalRangeGuard,
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
pub fn probe_mmio_slots(boot_params: &BootParams<'_>) -> MmioSlots {
    // Virtio MMIO addresses are discovered via fw_cfg, so skip probing
    // if it is not present.
    if !boot_params.has_fw_cfg_port() {
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
        let page_base = phys_addr.page_align();
        let page_offset = phys_addr.page_offset();

        if !phys_addr.is_aligned_to::<VirtIOHeader>() {
            log::warn!("MmioSlots: MMIO device at {phys_addr:x} is not properly aligned");
            continue;
        }

        if phys_addr.crosses_page(core::mem::size_of::<VirtIOHeader>()) {
            log::warn!("MmioSlots: MMIO device header at {phys_addr:x} crosses a page boundary");
            continue;
        }

        // If multiple devices reside in the same page, each gets its own
        // mapping, which is slightly wasteful but avoids shared-ownership
        // complexity.
        let Ok(mem) = map_global_range_4k_shared(page_base, PAGE_SIZE, PTEntryFlags::data()) else {
            log::warn!("MmioSlots: Failed to map MMIO region at {addr:x}");
            continue;
        };

        // Not expected to fail, because mem exists.
        let header = NonNull::new((mem.addr() + page_offset).as_mut_ptr()).unwrap();

        // SAFETY: The address is valid, mapped by `map_global_range_4k_shared`, and verified
        // to be VirtIOHeader-aligned by the guard above.
        // The memory region has the same lifetime of the MmioSlot structure which will be consumed by the driver.
        // Note: QEMU places each MMIO slot on its own page for us, thus mmio_size = PAGE_SIZE.
        let Ok(transport) = (unsafe { MmioTransport::new(header, PAGE_SIZE) }) else {
            // Currently QEMU advertises _all_ slots, regardless they are empty or not.
            log::debug!("MmioSlots: {addr:x} empty");
            continue;
        };

        log::info!("MmioSlots: Found {:?} at {addr:x}", transport.device_type());

        let slot_type = MmioSlot {
            transport,
            mmio_range: mem,
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
