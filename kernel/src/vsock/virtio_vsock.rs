// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Luigi Leonardi <leonardi@redhat.com>

use core::sync::atomic::Ordering;

use crate::error::SvsmError;
use crate::vsock::api::VsockDriver;
use crate::vsock::{VsockError, VSOCK_DEVICE};
extern crate alloc;
use crate::virtio::devices::{MMIOSlot, VirtIOVsockDevice, MMIO_SLOTS};
use alloc::boxed::Box;

use virtio_drivers::device::socket::{ConnectionStatus, VsockAddr};
pub struct VirtIOVsockDriver(Box<VirtIOVsockDevice>);

impl core::fmt::Debug for VirtIOVsockDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtIOVsockDriver").finish()
    }
}

pub fn initialize_vsock() {
    let mut binding = MMIO_SLOTS.lock_write();
    let slots = binding.as_deref_mut();
    if slots.is_none() {
        return;
    }

    let driver = slots
        .unwrap()
        .iter_mut()
        .filter(|slot| slot.free)
        .find_map(|slot| VirtIOVsockDriver::new(slot).ok());

    if driver.is_none() {
        log::info!("virtio-vsock device not found");
        return;
    }

    VSOCK_DEVICE
        .init(Box::new(driver.unwrap()))
        .expect("vsock driver already initialized");
}

impl VirtIOVsockDriver {
    pub fn new(mmio_slot: &mut MMIOSlot) -> Result<Self, SvsmError> {
        Ok(VirtIOVsockDriver(VirtIOVsockDevice::new(mmio_slot)?))
    }
}

impl VsockDriver for VirtIOVsockDriver {
    fn connect(&self, remote_cid: u64, local_port: u32, remote_port: u32) -> Result<(), SvsmError> {
        let server_address = VsockAddr {
            cid: remote_cid,
            port: remote_port,
        };

        self.0
            .device
            .locked_do(|dev| dev.connect(server_address, local_port))
            .map_err(VsockError::from)?;

        loop {
            let mut dev = self.0.device.lock();

            dev.wait_for_event().map_err(VsockError::from)?;
            let status = dev
                .get_connection_status(server_address, local_port)
                .map_err(VsockError::from)?;

            match status {
                ConnectionStatus::Connected => {
                    return Ok(());
                }
                ConnectionStatus::Connecting => {}
                _ => {
                    return Err(SvsmError::Vsock(VsockError::NotConnected));
                }
            }
        }
    }

    fn recv(
        &self,
        remote_cid: u64,
        local_port: u32,
        remote_port: u32,
        buffer: &mut [u8],
    ) -> Result<usize, SvsmError> {
        let mut total_received: usize = 0;

        loop {
            let mut dev = self.0.device.lock();

            let server_address = VsockAddr {
                cid: remote_cid,
                port: remote_port,
            };

            let received = match dev.recv(server_address, local_port, &mut buffer[total_received..])
            {
                Ok(value) => value,
                Err(error) => {
                    if total_received > 0 {
                        return Ok(total_received);
                    } else {
                        return Err(SvsmError::Vsock(VsockError::from(error)));
                    }
                }
            };
            log::debug!("[vsock] received: {received}");

            total_received += received;

            let result = dev.update_credit(server_address, local_port);
            if result.is_err() || total_received == buffer.len() {
                break;
            }

            dev.wait_for_event().map_err(VsockError::from)?;
        }

        Ok(total_received)
    }

    fn send(
        &self,
        remote_cid: u64,
        local_port: u32,
        remote_port: u32,
        buffer: &[u8],
    ) -> Result<usize, SvsmError> {
        let mut dev = self.0.device.lock();

        let server_address = VsockAddr {
            cid: remote_cid,
            port: remote_port,
        };

        dev.send(server_address, local_port, buffer)
            .map_err(VsockError::from)?;
        Ok(buffer.len())
    }

    fn shutdown(
        &self,
        remote_cid: u64,
        local_port: u32,
        remote_port: u32,
    ) -> Result<(), SvsmError> {
        let mut dev = self.0.device.lock();

        let server_address = VsockAddr {
            cid: remote_cid,
            port: remote_port,
        };

        dev.shutdown(server_address, local_port)
            .map_err(VsockError::from)?;
        Ok(())
    }

    fn force_shutdown(
        &self,
        remote_cid: u64,
        local_port: u32,
        remote_port: u32,
    ) -> Result<(), SvsmError> {
        let mut dev = self.0.device.lock();
        let server_address = VsockAddr {
            cid: remote_cid,
            port: remote_port,
        };

        dev.force_close(server_address, local_port)
            .map_err(VsockError::from)?;
        Ok(())
    }

    fn get_first_free_port(&self) -> Result<u32, SvsmError> {
        Ok(self.0.first_free_port.fetch_add(1, Ordering::Relaxed))
    }
}

impl From<virtio_drivers::Error> for VsockError {
    fn from(e: virtio_drivers::Error) -> Self {
        use virtio_drivers::device::socket::SocketError;
        use virtio_drivers::Error::SocketDeviceError;

        match e {
            SocketDeviceError(SocketError::ConnectionExists) => VsockError::ConnectionExists,
            SocketDeviceError(SocketError::NotConnected) => VsockError::NotConnected,
            SocketDeviceError(SocketError::PeerSocketShutdown) => VsockError::PeerSocketShutdown,
            _ => VsockError::DriverError,
        }
    }
}
