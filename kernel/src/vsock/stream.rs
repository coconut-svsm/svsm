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

#[derive(Debug, Eq, PartialEq)]
enum VsockStreamStatus {
    Connected,
    Closed,
}

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
///
/// // Explicitly shut down the connection
/// stream.shutdown()?;
/// # Ok::<(), error::SvsmError>(())
/// ```
///
/// # Connection Lifecycle
///
/// - A stream is created in the `Connected` state via [`connect()`](Self::connect).
/// - It can be explicitly closed using [`shutdown()`](Self::shutdown).
/// - When dropped, the stream automatically performs a force shutdown if still connected.
#[derive(Debug)]
pub struct VsockStream {
    local_port: u32,
    remote_port: u32,
    remote_cid: u64,
    status: VsockStreamStatus,
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
    /// - The VSOCK device is not available (`VsockError::DriverError`)
    /// - No free local ports are available
    /// - The connection fails
    pub fn connect(remote_port: u32, remote_cid: u64) -> Result<Self, SvsmError> {
        VSOCK_DEVICE
            .try_get_inner()
            .map_err(|_| VsockError::DriverError)?;

        let local_port = VSOCK_DEVICE.get_first_free_port()?;
        VSOCK_DEVICE.connect(remote_cid, local_port, remote_port)?;

        Ok(Self {
            local_port,
            remote_port,
            remote_cid,
            status: VsockStreamStatus::Connected,
        })
    }

    /// Gracefully shuts down the VSOCK connection.
    ///
    /// Closes the connection and transitions the stream to the `Closed` state.
    /// After calling this method, any subsequent read or write operations will fail.
    ///
    /// # Returns
    ///
    /// Returns `Ok()` on successful shutdown, or an error if:
    /// - The VSOCK device is not available (`VsockError::DriverError`)
    /// - The shutdown operation fails
    pub fn shutdown(&mut self) -> Result<(), SvsmError> {
        VSOCK_DEVICE
            .try_get_inner()
            .map_err(|_| VsockError::DriverError)?;

        self.status = VsockStreamStatus::Closed;
        VSOCK_DEVICE.shutdown(self.remote_cid, self.local_port, self.remote_port)
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
    /// Returns the number of bytes read on success, or an error if:
    /// - The VSOCK device is not available (`VsockError::DriverError`)
    /// - The stream has been shut down (`VsockError::SocketShutdown`)
    ///
    /// # Note
    ///
    /// This method returns `Ok(0)` if the peer shut the connection down.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err> {
        VSOCK_DEVICE
            .try_get_inner()
            .map_err(|_| VsockError::DriverError)?;

        if self.status == VsockStreamStatus::Closed {
            return Err(SvsmError::Vsock(VsockError::SocketShutdown));
        }

        match VSOCK_DEVICE.recv(self.remote_cid, self.local_port, self.remote_port, buf) {
            Ok(value) => Ok(value),
            Err(SvsmError::Vsock(VsockError::NotConnected)) => Ok(0),
            Err(SvsmError::Vsock(VsockError::SocketShutdown)) => Ok(0),
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
    /// - The VSOCK device is not available (`VsockError::DriverError`)
    /// - The send operation fails
    fn write(&mut self, buf: &[u8]) -> Result<usize, SvsmError> {
        VSOCK_DEVICE
            .try_get_inner()
            .map_err(|_| VsockError::DriverError)?;

        if self.status == VsockStreamStatus::Closed {
            return Err(SvsmError::Vsock(VsockError::SocketShutdown));
        }

        VSOCK_DEVICE.send(self.remote_cid, self.local_port, self.remote_port, buf)
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        if self.status == VsockStreamStatus::Closed || VSOCK_DEVICE.try_get_inner().is_err() {
            return;
        }

        let _ = VSOCK_DEVICE.force_shutdown(self.remote_cid, self.local_port, self.remote_port);
    }
}

#[cfg(all(test, test_in_svsm))]
mod tests {
    use crate::{testutils::has_test_iorequests, vsock::VMADDR_CID_HOST};

    use super::*;

    fn start_vsock_server_host() {
        use crate::serial::Terminal;
        use crate::testing::{IORequest, svsm_test_io};

        let sp = svsm_test_io().unwrap();

        sp.put_byte(IORequest::StartVsockServer as u8);

        let _ = sp.get_byte();
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_vsock_double_connect() {
        if !has_test_iorequests() {
            return;
        }

        start_vsock_server_host();

        let remote_port: u32 = 12345;

        let mut stream =
            VsockStream::connect(remote_port, VMADDR_CID_HOST).expect("connection failed");

        VsockStream::connect(remote_port, VMADDR_CID_HOST)
            .expect_err("The second connection operation was expected to fail, but it succeeded.");

        stream.shutdown().expect("shutdown failed");
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_vsock_write() {
        if !has_test_iorequests() {
            return;
        }

        start_vsock_server_host();

        let remote_port: u32 = 12345;

        let mut stream =
            VsockStream::connect(remote_port, VMADDR_CID_HOST).expect("connection failed");

        let buffer: &[u8] = b"Hello world!";

        let n_bytes = stream.write(buffer).expect("write failed");
        assert!(n_bytes == buffer.len(), "Sent less bytes than requested");

        stream.shutdown().expect("shutdown failed");
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_vsock_read() {
        if !has_test_iorequests() {
            return;
        }

        start_vsock_server_host();

        let remote_port: u32 = 12345;

        let mut stream =
            VsockStream::connect(remote_port, VMADDR_CID_HOST).expect("connection failed");

        let mut buffer: [u8; 11] = [0; 11];
        let n_bytes = stream.read(&mut buffer).expect("read failed");
        assert!(
            n_bytes == buffer.len(),
            "Received less bytes than requested"
        );

        let string = core::str::from_utf8(&buffer).unwrap();
        log::info!("received: {string:?}");

        stream.shutdown().expect("shutdown failed");
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_vsock_read_shutdown() {
        if !has_test_iorequests() {
            return;
        }

        start_vsock_server_host();

        let remote_port: u32 = 12345;

        let mut stream =
            VsockStream::connect(remote_port, VMADDR_CID_HOST).expect("connection failed");

        stream.shutdown().expect("shutdown failed");

        let mut buffer: [u8; 11] = [0; 11];
        stream
            .read(&mut buffer)
            .expect_err("The read operation was expected to fail, but it succeeded");
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_virtio_vsock_write_shutdown() {
        if !has_test_iorequests() {
            return;
        }

        start_vsock_server_host();

        let remote_port: u32 = 12345;

        let mut stream =
            VsockStream::connect(remote_port, VMADDR_CID_HOST).expect("connection failed");

        stream.shutdown().expect("shutdown failed");

        stream
            .write(b"hello world")
            .expect_err("The write operation was expected to fail, but it succeeded");
    }
}
