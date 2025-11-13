// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Luigi Leonardi <leonardi@redhat.com>

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VsockError {
    /// A connection already exists.
    ConnectionExists,
    /// The device is not connected to any peer.
    NotConnected,
    /// The peer socket has shutdown.
    PeerSocketShutdown,
    /// The local socket has been shutdown.
    SocketShutdown,
    /// Generic error for socket operations on a vsock device.
    DriverError,
}
