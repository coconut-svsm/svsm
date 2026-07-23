// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Luigi Leonardi <leonardi@redhat.com>

use crate::{
    error::SvsmError,
    io::{Read, Write},
    vsock::{VSOCK_DEVICE, VsockError},
};

/// A vsock stream for communication between a virtual machine
/// and its host.
///
/// `VsockStream` provides a TCP-like socket interface over the VSOCK transport,
/// which is designed for communication between a guest VM and its host.
/// It implements the [`Read`] and [`Write`] traits for I/O operations.
///
/// # Examples
///
/// ```no_run
/// use crate::svsm::io::{Read, Write};
/// use crate::svsm::vsock::{VMADDR_CID_HOST, stream::VsockStream};
/// use svsm::error;
///
/// // Connect to host on port 12345
/// let mut stream = VsockStream::connect(12345, VMADDR_CID_HOST)?;
///
/// // Write data
/// let data = b"Hello, host!";
/// stream.write(data)?;
///
/// // Read response
/// let mut buffer = [0u8; 10];
/// let n = stream.read(&mut buffer)?;
/// # Ok::<(), error::SvsmError>(())
/// ```
///
/// # Connection Lifecycle
///
/// - A stream is created in the `Connected` state via [`connect()`](Self::connect).
/// - When dropped, the stream is automatically shutdown.
#[derive(Debug)]
pub struct VsockStream {
    local_port: u32,
    remote_port: u32,
    remote_cid: u32,
}

impl VsockStream {
    /// Establishes a VSOCK connection to a remote endpoint.
    ///
    /// Creates a new VSOCK stream and connects to the specified remote port and CID
    /// The local port is automatically assigned from available ports.
    ///
    /// # Arguments
    ///
    /// * `remote_port` - The port number on the remote endpoint to connect to.
    /// * `remote_cid` - The CID of the remote endpoint.
    ///
    /// # Returns
    ///
    /// Returns a connected `VsockStream` on success, or an error if:
    /// - The VSOCK device is not available (`VsockError::DeviceNotAvailable`)
    /// - No free local ports are available
    /// - The connection fails
    pub fn connect(remote_port: u32, remote_cid: u32) -> Result<Self, SvsmError> {
        let device = VSOCK_DEVICE
            .try_get_inner()
            .map_err(|_| SvsmError::Vsock(VsockError::DeviceNotAvailable))?;

        let local_port = device.get_first_free_port()?;
        device.connect(remote_cid, local_port, remote_port)?;

        Ok(Self {
            local_port,
            remote_port,
            remote_cid,
        })
    }
}

impl Read for VsockStream {
    type Err = SvsmError;

    /// Perform a blocking read from the VSOCK stream into the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to read data into.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes read on success, or 0 if the peer shut
    /// the connection down.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The VSOCK device is not available (`VsockError::DeviceNotAvailable`)
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err> {
        let device = VSOCK_DEVICE
            .try_get_inner()
            .map_err(|_| SvsmError::Vsock(VsockError::DeviceNotAvailable))?;

        match device.recv(self.remote_cid, self.local_port, self.remote_port, buf) {
            Ok(value) => Ok(value),
            Err(SvsmError::Vsock(VsockError::NotConnected)) => Ok(0),
            Err(SvsmError::Vsock(VsockError::PeerSocketShutdown)) => Ok(0),
            Err(e) => Err(e),
        }
    }
}

impl Write for VsockStream {
    type Err = SvsmError;

    /// Writes data from the provided buffer to the VSOCK stream.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer containing data to write.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written on success, or an error if:
    /// - The VSOCK device is not available (`VsockError::DeviceNotAvailable`)
    /// - The send operation fails
    fn write(&mut self, buf: &[u8]) -> Result<usize, SvsmError> {
        let device = VSOCK_DEVICE
            .try_get_inner()
            .map_err(|_| SvsmError::Vsock(VsockError::DeviceNotAvailable))?;

        device.send(self.remote_cid, self.local_port, self.remote_port, buf)
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        if let Ok(device) = VSOCK_DEVICE.try_get_inner() {
            let _ = device.shutdown(self.remote_cid, self.local_port, self.remote_port, true);
        }
    }
}

#[cfg(all(test, test_in_svsm))]
mod tests {
    use crate::{testutils::has_test_iorequests, vsock::VMADDR_CID_HOST, vsock::VMADDR_PORT_ANY};

    use super::*;

    fn start_vsock_server_host() -> u32 {
        use crate::serial::Terminal;
        use crate::testing::{IORequest, svsm_test_io};

        let sp = svsm_test_io().unwrap();

        sp.put_byte(IORequest::StartVsockServer as u8);

        // Read port as 4 raw bytes (big-endian, sent by the host via xxd -p -r)
        let mut port_bytes = [0u8; 4];
        for byte in &mut port_bytes {
            *byte = sp.get_byte();
        }

        let port = u32::from_be_bytes(port_bytes);
        assert_ne!(port, VMADDR_PORT_ANY, "host failed to start vsock server");
        port
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_vsock_double_connect() {
        if !has_test_iorequests() {
            return;
        }

        let remote_port = start_vsock_server_host();

        let mut stream =
            VsockStream::connect(remote_port, VMADDR_CID_HOST).expect("connection failed");

        // Read the message to ensure the server has accepted the connection
        // and closed its listening socket before we attempt the second connect.
        let mut buffer = [0u8; 11];
        stream.read(&mut buffer).expect("read failed");
        drop(stream);

        VsockStream::connect(remote_port, VMADDR_CID_HOST)
            .expect_err("The second connection operation was expected to fail, but it succeeded.");
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_vsock_write() {
        if !has_test_iorequests() {
            return;
        }

        let remote_port = start_vsock_server_host();

        let mut stream =
            VsockStream::connect(remote_port, VMADDR_CID_HOST).expect("connection failed");

        let buffer: &[u8] = b"Hello world!";

        let n_bytes = stream.write(buffer).expect("write failed");
        assert_eq!(n_bytes, buffer.len(), "Sent less bytes than requested");
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_vsock_read() {
        if !has_test_iorequests() {
            return;
        }

        let remote_port = start_vsock_server_host();

        let mut stream =
            VsockStream::connect(remote_port, VMADDR_CID_HOST).expect("connection failed");

        let mut buffer: [u8; 11] = [0; 11];
        let n_bytes = stream.read(&mut buffer).expect("read failed");
        assert_eq!(n_bytes, buffer.len(), "Received less bytes than requested");

        let string = core::str::from_utf8(&buffer).unwrap();
        assert_eq!(string, "hello_world", "Received wrong message");
    }
}
