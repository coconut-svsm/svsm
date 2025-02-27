#![no_std]
#![no_main]
#![deny(warnings)]

#[macro_use]
extern crate log;

extern crate alloc;
extern crate opensbi_rt;

use alloc::vec;
use core::ptr::NonNull;
use flat_device_tree::{node::FdtNode, standard_nodes::Compatible, Fdt};
use log::LevelFilter;
use virtio_drivers::{
    device::blk::VirtIOBlk,
    transport::{
        mmio::{MmioTransport, VirtIOHeader},
        DeviceType, Transport,
    },
};
use virtio_impl::HalImpl;

mod virtio_impl;

#[no_mangle]
extern "C" fn main(_hartid: usize, device_tree_paddr: usize) {
    log::set_max_level(LevelFilter::Info);
    init_dt(device_tree_paddr);
    info!("test end");
}

fn init_dt(dtb: usize) {
    info!("device tree @ {:#x}", dtb);
    // Safe because the pointer is a valid pointer to unaliased memory.
    let fdt = unsafe { Fdt::from_ptr(dtb as *const u8).unwrap() };
    walk_dt(fdt);
}

fn walk_dt(fdt: Fdt) {
    for node in fdt.all_nodes() {
        if let Some(compatible) = node.compatible() {
            if compatible.all().any(|s| s == "virtio,mmio") {
                virtio_probe(node);
            }
        }
    }
}

fn virtio_probe(node: FdtNode) {
    if let Some(reg) = node.reg().next() {
        let paddr = reg.starting_address as usize;
        let size = reg.size.unwrap();
        let vaddr = paddr;
        info!("walk dt addr={:#x}, size={:#x}", paddr, size);
        info!(
            "Device tree node {}: {:?}",
            node.name,
            node.compatible().map(Compatible::first),
        );
        let header = NonNull::new(vaddr as *mut VirtIOHeader).unwrap();
        match unsafe { MmioTransport::<HalImpl>::new(header) } {
            Err(e) => warn!("Error creating VirtIO MMIO transport: {}", e),
            Ok(transport) => {
                info!(
                    "Detected virtio MMIO device with vendor id {:#X}, device type {:?}, version {:?}",
                    transport.vendor_id(),
                    transport.device_type(),
                    transport.version(),
                );
                virtio_device(transport);
            }
        }
    }
}

fn virtio_device(transport: impl Transport) {
    match transport.device_type() {
        DeviceType::Block => virtio_blk(transport),
        t => warn!("Unrecognized virtio device: {:?}", t),
    }
}

fn virtio_blk<T: Transport>(transport: T) {
    let mut blk = VirtIOBlk::<HalImpl, T>::new(transport).expect("failed to create blk driver");
    let mut input = vec![0xffu8; 512];
    let mut output = vec![0; 512];
    for i in 0..32 {
        for x in input.iter_mut() {
            *x = i as u8;
        }
        blk.write_blocks(i, &input).expect("failed to write");
        blk.read_blocks(i, &mut output).expect("failed to read");
        assert_eq!(input, output);
    }
    info!("virtio-blk test finished");
}
