use crate::address::PhysAddr;
use crate::error::SvsmError;
extern crate alloc;
use crate::fw_cfg::FwCfg;
use crate::io::{Read, Write};
use crate::platform::SVSM_PLATFORM;
use crate::virtio::devices::VirtIOVsockDevice;
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

impl VirtIOVsockDriver {
    pub fn new(mmio_base: PhysAddr) -> Result<Self, SvsmError> {
        Ok(VirtIOVsockDriver(VirtIOVsockDevice::new(mmio_base)?))
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

            let received = dev.recv(server_address, local_port, &mut buffer[first_clean_pos..])?;
            log::info!("[vsock] received: {received}");
            dev.update_credit(server_address, local_port)?;

            first_clean_pos += received;

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

    pub fn close(&self, remote_cid: u64, local_port: u32, remote_port: u32) -> Result<(), Error> {
        let mut dev = self.0.device.lock();

        let server_address = VsockAddr {
            cid: remote_cid,
            port: remote_port,
        };

        dev.shutdown(server_address, local_port)
    }
}

#[derive(Debug)]
pub struct VsockStream {
    local_port: u32,
    remote_port: u32,
    remote_cid: u64,
    driver: VirtIOVsockDriver,
}

impl VsockStream {
    pub fn connect(local_port: u32, remote_port: u32, remote_cid: u64) -> Result<Self, SvsmError> {
        let cfg = FwCfg::new(SVSM_PLATFORM.get_io_port());

        let driver = cfg
            .get_virtio_mmio_addresses()
            .unwrap_or_default()
            .iter()
            .find_map(|a| VirtIOVsockDriver::new(PhysAddr::from(*a)).ok())
            .ok_or(SvsmError::Vsock(VsockError::Failed))?;

        if driver.connect(remote_cid, local_port, remote_port).is_err() {
            return Err(SvsmError::Vsock(VsockError::ConnectFailed));
        }

        Ok(Self {
            local_port,
            remote_port,
            remote_cid,
            driver,
        })
    }

    pub fn close(&self) -> Result<(), SvsmError> {
        self.driver
            .close(self.remote_cid, self.local_port, self.remote_port)
            .map_err(|_| SvsmError::Vsock(VsockError::Failed))
    }
}

impl Read for VsockStream {
    type Err = SvsmError;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err> {
        self.driver
            .recv(self.remote_cid, self.local_port, self.remote_port, buf)
            .map_err(|_| SvsmError::Vsock(VsockError::RecvFailed))
    }
}

impl Write for VsockStream {
    type Err = SvsmError;

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err> {
        self.driver
            .send(self.remote_cid, self.local_port, self.remote_port, buf)
            .map_err(|_| SvsmError::Vsock(VsockError::SendFailed))
    }
}

#[cfg(all(test, test_in_svsm))]
mod tests {
    use crate::{
        address::PhysAddr, fw_cfg::FwCfg, platform::SVSM_PLATFORM, testutils::has_test_iorequests,
    };

    use super::*;

    fn start_vsock_server_host() {
        use crate::serial::Terminal;
        use crate::testing::{svsm_test_io, IORequest};

        let sp = svsm_test_io().unwrap();

        sp.put_byte(IORequest::StartVsockServer as u8);

        let _ = sp.get_byte();
    }

    fn get_vsock_device() -> VirtIOVsockDriver {
        let cfg = FwCfg::new(SVSM_PLATFORM.get_io_port());

        let dev = cfg
            .get_virtio_mmio_addresses()
            .unwrap_or_default()
            .iter()
            .find_map(|a| VirtIOVsockDriver::new(PhysAddr::from(*a)).ok())
            .expect("No virtio-vsock device found");

        dev
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_vsock() {
        if !has_test_iorequests() {
            return;
        }

        start_vsock_server_host();

        let device = get_vsock_device();

        let cid = 2;
        let local_port = 1234;
        let remote_port = 12345;

        device
            .connect(cid, local_port, remote_port)
            .expect("Connection failed");

        device
            .connect(cid, local_port, remote_port)
            .expect_err("The second connection operation was expected to fail, but it succeeded.");

        let mut buffer: [u8; 11] = [0; 11];
        let n_bytes = device
            .recv(cid, local_port, remote_port, &mut buffer)
            .expect("Recv failed");

        assert!(
            n_bytes == buffer.len(),
            "Received less bytes than requested"
        );

        let string = core::str::from_utf8(&buffer).unwrap();
        log::info!("received: {string:?}");

        device
            .close(cid, local_port, remote_port)
            .expect("Close failed");

        device
            .send(cid, local_port, remote_port, &buffer)
            .expect_err("The send operation was expected to fail, but it succeeded.");
    }
}
