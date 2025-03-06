use crate::{
    address::PhysAddr,
    block::{api::BlockDriver, virtio_blk::VirtIOBlkDriver},
    fw_cfg::FwCfg,
};
extern crate alloc;
use alloc::vec::Vec;

pub fn run_demo(fw_cfg: &FwCfg<'_>) {
    log::info!("Virtio blk demo");

    let addresses = fw_cfg.get_virtio_mmio_addresses().unwrap_or_default();

    log::info!(
        " Got these virtio mmio addresses from fw_cfg: {:x?}",
        addresses
    );

    let mut devices: Vec<VirtIOBlkDriver> = addresses
        .iter()
        .inspect(|a| log::info!("  checking for device at {a:016x}"))
        .filter_map(|a| VirtIOBlkDriver::new(PhysAddr::from(*a)).ok())
        .inspect(|_d| log::info!("   found a device!"))
        .collect();

    log::info!(" found {} virtio_blk devides", devices.len());

    if let Some(dev) = devices.pop() {
        log::info!("First device's size is {} bytes", dev.size());
    }

    panic!("--- END OF DEMO ---");
}
