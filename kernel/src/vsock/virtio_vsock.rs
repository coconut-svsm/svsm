use crate::error::SvsmError;
use core::ops::DerefMut;
extern crate alloc;
use crate::io::{Read, Write};
use crate::locking::RWLock;
use crate::virtio::devices::{MMIOSlot, VirtIOVsockDevice, MMIO_SLOTS};
use crate::vsock::VsockError;
use alloc::boxed::Box;

use virtio_drivers::device::socket::{ConnectionStatus, SocketError, VsockAddr};
use virtio_drivers::Error;
pub struct VirtIOVsockDriver(Box<VirtIOVsockDevice>);

impl core::fmt::Debug for VirtIOVsockDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtIOVsockDriver").finish()
    }
}

static VSOCK_DEVICE: RWLock<Option<VirtIOVsockDriver>> = RWLock::new(None);

pub fn initialize_vsock() {
    let mut binding = MMIO_SLOTS.lock_write();
    let slots = binding.as_deref_mut();

    let driver = slots
        .unwrap()
        .iter_mut()
        .filter(|slot| slot.free)
        .find_map(|slot| VirtIOVsockDriver::new(slot).ok());

    *VSOCK_DEVICE.lock_write().deref_mut() = driver;
}

impl VirtIOVsockDriver {
    pub fn new(mmio_slot: &mut MMIOSlot) -> Result<Self, SvsmError> {
        Ok(VirtIOVsockDriver(VirtIOVsockDevice::new(mmio_slot)?))
    }

    pub fn connect(&self, remote_cid: u64, local_port: u32, remote_port: u32) -> Result<(), Error> {
        let server_address = VsockAddr {
            cid: remote_cid,
            port: remote_port,
        };

        self.0
            .device
            .locked_do(|dev| dev.connect(server_address, local_port))?;

        loop {
            let mut dev = self.0.device.lock();

            dev.wait_for_event()?;
            let status = dev.get_connection_status(server_address, local_port)?;

            match status {
                ConnectionStatus::Connected => {
                    return Ok(());
                }
                ConnectionStatus::Connecting => {}
                _ => {
                    return Err(SocketError::NotConnected.into());
                }
            }
        }
    }

    pub fn recv(
        &self,
        remote_cid: u64,
        local_port: u32,
        remote_port: u32,
        buffer: &mut [u8],
    ) -> Result<usize, Error> {
        let mut first_clean_pos: usize = 0;

        loop {
            let mut dev = self.0.device.lock();

            let server_address = VsockAddr {
                cid: remote_cid,
                port: remote_port,
            };

            // In case of error return the bytes read so far
            let received =
                match dev.recv(server_address, local_port, &mut buffer[first_clean_pos..]) {
                    Ok(value) => value,
                    Err(error) => {
                        if first_clean_pos > 0 {
                            return Ok(first_clean_pos);
                        } else {
                            return Err(error);
                        }
                    }
                };
            log::info!("[vsock] received: {received}");

            first_clean_pos += received;

            dev.update_credit(server_address, local_port)?;

            if received < buffer.len() && first_clean_pos != buffer.len() {
                dev.wait_for_event()?;
            } else {
                break;
            }
        }

        Ok(buffer.len())
    }

    pub fn send(
        &self,
        remote_cid: u64,
        local_port: u32,
        remote_port: u32,
        buffer: &[u8],
    ) -> Result<usize, Error> {
        let mut dev = self.0.device.lock();

        let server_address = VsockAddr {
            cid: remote_cid,
            port: remote_port,
        };

        dev.send(server_address, local_port, buffer)?;
        Ok(buffer.len())
    }

    pub fn shutdown(
        &self,
        remote_cid: u64,
        local_port: u32,
        remote_port: u32,
    ) -> Result<(), Error> {
        let mut dev = self.0.device.lock();

        let server_address = VsockAddr {
            cid: remote_cid,
            port: remote_port,
        };

        dev.shutdown(server_address, local_port)
    }

    pub fn force_close(
        &self,
        remote_cid: u64,
        local_port: u32,
        remote_port: u32,
    ) -> Result<(), Error> {
        let mut dev = self.0.device.lock();
        let server_address = VsockAddr {
            cid: remote_cid,
            port: remote_port,
        };

        dev.force_close(server_address, local_port)
    }
}

#[derive(Debug, Eq, PartialEq)]
enum VsockStreamStatus {
    Connected,
    Closed,
}

#[derive(Debug)]
pub struct VsockStream {
    local_port: u32,
    remote_port: u32,
    remote_cid: u64,
    status: VsockStreamStatus,
}

impl VsockStream {
    pub fn connect(local_port: u32, remote_port: u32, remote_cid: u64) -> Result<Self, SvsmError> {
        let device_guard = VSOCK_DEVICE.lock_read();
        let device = device_guard
            .as_ref()
            .ok_or(SvsmError::Vsock(VsockError::Failed))?;

        if device.connect(remote_cid, local_port, remote_port).is_err() {
            return Err(SvsmError::Vsock(VsockError::ConnectFailed));
        }

        Ok(Self {
            local_port,
            remote_port,
            remote_cid,
            status: VsockStreamStatus::Connected,
        })
    }

    pub fn shutdown(&mut self) -> Result<(), SvsmError> {
        let device_guard = VSOCK_DEVICE.lock_read();
        let device = device_guard
            .as_ref()
            .ok_or(SvsmError::Vsock(VsockError::Failed))?;

        self.status = VsockStreamStatus::Closed;
        device
            .shutdown(self.remote_cid, self.local_port, self.remote_port)
            .map_err(|_| SvsmError::Vsock(VsockError::Failed))
    }
}

impl Read for VsockStream {
    type Err = SvsmError;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err> {
        let device_guard = VSOCK_DEVICE.lock_read();
        let device = device_guard
            .as_ref()
            .ok_or(SvsmError::Vsock(VsockError::Failed))?;

        if self.status == VsockStreamStatus::Closed {
            return Err(SvsmError::Vsock(VsockError::RecvFailed));
        }

        match device.recv(self.remote_cid, self.local_port, self.remote_port, buf) {
            Ok(some) => Ok(some),
            Err(_e) => Ok(0),
        }
    }
}

impl Write for VsockStream {
    type Err = SvsmError;

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err> {
        let device_guard = VSOCK_DEVICE.lock_read();
        let device = device_guard
            .as_ref()
            .ok_or(SvsmError::Vsock(VsockError::Failed))?;

        device
            .send(self.remote_cid, self.local_port, self.remote_port, buf)
            .map_err(|_| SvsmError::Vsock(VsockError::SendFailed))
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        if self.status == VsockStreamStatus::Closed {
            return;
        }

        let device_guard = VSOCK_DEVICE.lock_read();
        let device = device_guard.as_ref().unwrap();

        let _ = device.force_close(self.remote_cid, self.local_port, self.remote_port);
    }
}

#[cfg(all(test, test_in_svsm))]
mod tests {
    use crate::testutils::has_test_iorequests;

    use super::*;

    fn start_vsock_server_host() {
        use crate::serial::Terminal;
        use crate::testing::{svsm_test_io, IORequest};

        let sp = svsm_test_io().unwrap();

        sp.put_byte(IORequest::StartVsockServer as u8);

        let _ = sp.get_byte();
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_vsock() {
        if !has_test_iorequests() {
            return;
        }

        start_vsock_server_host();

        let cid = 2;
        let local_port = 1234;
        let remote_port = 12345;

        let mut stream =
            VsockStream::connect(local_port, remote_port, cid).expect("connection failed");

        VsockStream::connect(local_port, remote_port, cid)
            .expect_err("The second connection operation was expected to fail, but it succeeded.");

        let mut buffer: [u8; 11] = [0; 11];
        let n_bytes = stream.read(&mut buffer).expect("read failed");

        assert!(
            n_bytes == buffer.len(),
            "Received less bytes than requested"
        );

        let string = core::str::from_utf8(&buffer).unwrap();
        log::info!("received: {string:?}");

        stream.shutdown().expect("shutdown failed");

        stream
            .write(&buffer)
            .expect_err("The write operation was expected to fail, but it succeeded.");

        stream
            .read(&mut buffer)
            .expect_err("The read operation was expected to fail, but it succeeded");
    }
}
