// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Luigi Leonardi <leonardi@redhat.com>

use crate::error::SvsmError;

pub trait VsockTransport: Sync + Send {
    /// Establishes a connection to a remote vsock endpoint.
    ///
    /// This method initiates a connection to the specified remote CID and port
    /// using the provided local port. The call blocks until the connection is
    /// established or fails.
    ///
    /// # Parameters
    ///
    /// * `remote_cid` - The CID of the remote endpoint to connect to
    /// * `local_port` - The local port to use for this connection
    /// * `remote_port` - The remote port to connect to
    ///
    /// # Returns
    ///
    /// * `Ok()` if the connection was successfully established
    /// * `Err(SvsmError)` if the connection failed
    fn connect(&self, remote_cid: u64, local_port: u32, remote_port: u32) -> Result<(), SvsmError>;

    /// Sends data over an established vsock connection.
    ///
    /// Transmits the contents of the provided buffer to the remote endpoint.
    /// The connection must have been previously established via `connect()`.
    ///
    /// # Parameters
    ///
    /// * `remote_cid` - The CID of the remote endpoint
    /// * `local_port` - The local port of the connection
    /// * `remote_port` - The remote port of the connection
    /// * `buffer` - The data to send
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes successfully sent
    /// * `Err(SvsmError)` if the send operation failed
    fn send(
        &self,
        remote_cid: u64,
        local_port: u32,
        remote_port: u32,
        buffer: &[u8],
    ) -> Result<usize, SvsmError>;

    /// Receives data from an established vsock connection.
    ///
    /// Reads data from the remote endpoint into the provided buffer. This method
    /// blocks until all data is available or an error occurs, in such case
    /// returns all the received bytes, if any.
    /// The connection must have been previously established via `connect()`.
    ///
    /// # Parameters
    ///
    /// * `remote_cid` - The CID of the remote endpoint
    /// * `local_port` - The local port of the connection
    /// * `remote_port` - The remote port of the connection
    /// * `buffer` - The buffer to receive data into
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes successfully received
    /// * `Err(SvsmError)` if the receive operation failed
    fn recv(
        &self,
        remote_cid: u64,
        local_port: u32,
        remote_port: u32,
        buffer: &mut [u8],
    ) -> Result<usize, SvsmError>;

    /// Shuts down a vsock connection.
    ///
    /// Initiates a graceful shutdown of the connection telling the peer that we won't
    /// send or receive any more data.
    ///
    /// # Parameters
    ///
    /// * `remote_cid` - The CID of the remote endpoint
    /// * `local_port` - The local port of the connection
    /// * `remote_port` - The remote port of the connection
    /// * `force` - Forcibly terminates the connection, without waiting for peer confirm
    ///
    /// # Returns
    ///
    /// * `Ok()` if the shutdown was successful
    /// * `Err(SvsmError)` if the shutdown failed
    fn shutdown(
        &self,
        remote_cid: u64,
        local_port: u32,
        remote_port: u32,
        force: bool,
    ) -> Result<(), SvsmError>;

    /// Returns whether the given local port is currently in use.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - The port is in use
    /// * `Ok(false)` - The port is free
    /// * `Err(SvsmError)` if the check could not be performed
    fn is_local_port_used(&self, port: u32) -> Result<bool, SvsmError>;
}
