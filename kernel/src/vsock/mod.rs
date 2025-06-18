// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Luigi Leonardi <leonardi@redhat.com>

pub mod api;
pub mod error;
#[cfg(feature = "virtio-drivers")]
pub mod virtio_vsock;

pub use error::VsockError;
/// Well-known CID for the host.
pub const VMADDR_CID_HOST: u32 = 2;
pub const VMADDR_PORT_ANY: u32 = u32::MAX;

extern crate alloc;
use crate::{
    error::SvsmError, utils::immut_after_init::ImmutAfterInitCell, vsock::api::VsockTransport,
};
use alloc::boxed::Box;
use core::ops::Deref;
use core::sync::atomic::{AtomicU32, Ordering};

// Currently only one vsock device is supported.
static VSOCK_DEVICE: ImmutAfterInitCell<VsockDriver> = ImmutAfterInitCell::uninit();
// Ports below 1024 are reserved
const VSOCK_MIN_PORT: u32 = 1024;
// Number of maximum retries to get a local free port
const MAX_RETRIES: u32 = 5;

struct VsockDriver {
    first_free_port: AtomicU32,
    transport: Box<dyn VsockTransport>,
}

impl VsockDriver {
    /// Returns a free local port number for a new connection.
    ///
    /// Returns [`VsockError::NoPortsAvailable`] if all
    /// ports are already in use.
    fn get_first_free_port(&self) -> Result<u32, SvsmError> {
        for _ in 0..MAX_RETRIES {
            let candidate_port =
                self.first_free_port
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |port| {
                        if port >= VMADDR_PORT_ANY - 1 {
                            Some(VSOCK_MIN_PORT)
                        } else {
                            Some(port + 1)
                        }
                    });

            // The closure always returns Some, so this never fails.
            let candidate_port = candidate_port.unwrap();

            if !self.is_local_port_used(candidate_port)? {
                return Ok(candidate_port);
            }
        }

        Err(SvsmError::Vsock(VsockError::NoPortsAvailable))
    }
}

impl Deref for VsockDriver {
    type Target = dyn VsockTransport;

    fn deref(&self) -> &Self::Target {
        self.transport.as_ref()
    }
}
