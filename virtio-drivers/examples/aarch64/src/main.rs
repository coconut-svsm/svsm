#![no_std]
#![no_main]

extern crate alloc;

mod exceptions;
mod hal;
mod logger;
#[cfg(platform = "qemu")]
mod pl011;
#[cfg(platform = "qemu")]
use pl011 as uart;
#[cfg(platform = "crosvm")]
mod uart8250;
#[cfg(platform = "crosvm")]
use uart8250 as uart;

use buddy_system_allocator::LockedHeap;
use core::{mem::size_of, panic::PanicInfo, ptr::NonNull};
use flat_device_tree::{standard_nodes::Compatible, Fdt};
use hal::HalImpl;
use log::{debug, error, info, trace, warn, LevelFilter};
use smccc::{psci::system_off, Hvc};
use virtio_drivers::{
    device::{
        blk::VirtIOBlk,
        console::VirtIOConsole,
        socket::{
            VirtIOSocket, VsockAddr, VsockConnectionManager, VsockEventType, VMADDR_CID_HOST,
        },
    },
    transport::{
        mmio::{MmioTransport, VirtIOHeader},
        DeviceType, Transport,
    },
};

/// Base memory-mapped address of the primary PL011 UART device.
#[cfg(platform = "qemu")]
pub const UART_BASE_ADDRESS: usize = 0x900_0000;

/// The base address of the first 8250 UART.
#[cfg(platform = "crosvm")]
pub const UART_BASE_ADDRESS: usize = 0x3f8;

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::new();

static mut HEAP: [u8; 0x1000000] = [0; 0x1000000];

#[no_mangle]
extern "C" fn main(x0: u64, x1: u64, x2: u64, x3: u64) {
    logger::init(LevelFilter::Debug).unwrap();
    info!("virtio-drivers example started.");
    debug!(
        "x0={:#018x}, x1={:#018x}, x2={:#018x}, x3={:#018x}",
        x0, x1, x2, x3
    );

    // Safe because `HEAP` is only used here and `entry` is only called once.
    unsafe {
        // Give the allocator some memory to allocate.
        HEAP_ALLOCATOR
            .lock()
            .init(HEAP.as_mut_ptr() as usize, HEAP.len());
    }

    info!("Loading FDT from {:#018x}", x0);
    // Safe because the pointer is a valid pointer to unaliased memory.
    let fdt = unsafe { Fdt::from_ptr(x0 as *const u8).unwrap() };

    for node in fdt.all_nodes() {
        // Dump information about the node for debugging.
        trace!(
            "{}: {:?}",
            node.name,
            node.compatible().map(Compatible::first),
        );
        for range in node.reg() {
            trace!(
                "  {:#018x?}, length {:?}",
                range.starting_address,
                range.size
            );
        }

        // Check whether it is a VirtIO MMIO device.
        if let (Some(compatible), Some(region)) = (node.compatible(), node.reg().next()) {
            if compatible.all().any(|s| s == "virtio,mmio")
                && region.size.unwrap_or(0) > size_of::<VirtIOHeader>()
            {
                debug!("Found VirtIO MMIO device at {:?}", region);

                let header = NonNull::new(region.starting_address as *mut VirtIOHeader).unwrap();
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
    }

    system_off::<Hvc>().unwrap();
}

fn virtio_device(transport: impl Transport) {
    match transport.device_type() {
        DeviceType::Block => virtio_blk(transport),
        DeviceType::Console => virtio_console(transport),
        DeviceType::Socket => match virtio_socket(transport) {
            Ok(()) => info!("virtio-socket test finished successfully"),
            Err(e) => error!("virtio-socket test finished with error '{e:?}'"),
        },
        t => warn!("Unrecognized virtio device: {:?}", t),
    }
}

fn virtio_blk<T: Transport>(transport: T) {
    let mut blk = VirtIOBlk::<HalImpl, T>::new(transport).expect("failed to create blk driver");
    assert!(!blk.readonly());
    let mut input = [0xffu8; 512];
    let mut output = [0; 512];
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

fn virtio_console<T: Transport>(transport: T) {
    let mut console =
        VirtIOConsole::<HalImpl, T>::new(transport).expect("Failed to create console driver");
    if let Some(size) = console.size() {
        info!("VirtIO console {}", size);
    }
    for &c in b"Hello world on console!\n" {
        console.send(c).expect("Failed to send character");
    }
    let c = console.recv(true).expect("Failed to read from console");
    info!("Read {:?}", c);
    info!("virtio-console test finished");
}

fn virtio_socket<T: Transport>(transport: T) -> virtio_drivers::Result<()> {
    let mut socket = VsockConnectionManager::new(
        VirtIOSocket::<HalImpl, T>::new(transport).expect("Failed to create socket driver"),
    );
    let port = 1221;
    let host_address = VsockAddr {
        cid: VMADDR_CID_HOST,
        port,
    };
    info!("Connecting to host on port {port}...");
    socket.connect(host_address, port)?;
    let event = socket.wait_for_event()?;
    assert_eq!(event.source, host_address);
    assert_eq!(event.destination.port, port);
    assert_eq!(event.event_type, VsockEventType::Connected);
    info!("Connected to the host");

    const EXCHANGE_NUM: usize = 2;
    let messages = ["0-Ack. Hello from guest.", "1-Ack. Received again."];
    for k in 0..EXCHANGE_NUM {
        let mut buffer = [0u8; 24];
        let socket_event = socket.wait_for_event()?;
        let VsockEventType::Received { length, .. } = socket_event.event_type else {
            panic!("Received unexpected socket event {:?}", socket_event);
        };
        let read_length = socket.recv(host_address, port, &mut buffer)?;
        assert_eq!(length, read_length);
        info!(
            "Received message: {:?}({:?}), len: {:?}",
            buffer,
            core::str::from_utf8(&buffer[..length]),
            length
        );

        let message = messages[k % messages.len()];
        socket.send(host_address, port, message.as_bytes())?;
        info!("Sent message: {:?}", message);
    }
    socket.shutdown(host_address, port)?;
    info!("Shutdown the connection");
    Ok(())
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    error!("{}", info);
    system_off::<Hvc>().unwrap();
    loop {}
}
