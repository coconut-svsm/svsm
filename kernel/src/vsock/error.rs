// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Luigi Leonardi <leonardi@redhat.com>

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VsockError {
    /// There is an existing connection.
    ConnectionExists,
    /// The device is not connected to any peer.
    NotConnected,
    /// Peer socket is shutdown.
    PeerSocketShutdown,
    /// socket is shutdown.
    SocketShutdown,
    /// Generic error for socket operations on a vsock device.
    DriverError,
}
