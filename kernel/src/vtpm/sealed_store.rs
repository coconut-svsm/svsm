// SPDX-License-Identifier: MIT
//
// Pluggable storage backend for the sealed vTPM blob.
//
// The vTPM persistence cycle (`Provision` → seal → store, store → load →
// `Recover`) is intentionally decoupled from the underlying durable medium
// so that the same crypto path can be paired with different host-side
// storage strategies. Three backends are bundled:
//
//   * `StaticBufStore`  — in-CVM static buffer, survives warm reboots
//                         within the lifetime of the CVM (test / dev).
//   * `IgvmVarStore`    — IGVM variable interface (stubbed, TODO).
//   * `VsockHostStore`  — AF_VSOCK to a host-side helper that persists
//                         the blob on the host filesystem
//                         (feature-gated `vsock`).
//
// The trait is intentionally backend-agnostic so that it can be paired
// with the upcoming SVSM block-layer abstraction or with a KBS-backed
// stateful vTPM service without changing the persistence logic itself.

extern crate alloc;

use alloc::vec::Vec;

use crate::locking::SpinLock;
use crate::protocols::errors::SvsmReqError;

/// Persistent storage backend for the sealed vTPM blob.
///
/// Implementations must be safe to share across CPUs (`Send + Sync`);
/// concurrency control is the implementation's responsibility.
pub trait SealedBlobStore: Send + Sync {
    /// Return the previously saved blob, if any.
    ///
    /// `Ok(None)` indicates a cold boot or an empty backend; the caller
    /// should fall back to `VtpmBootMode::Provision`. A backend error is
    /// distinct from an empty backend and is reported via `Err`.
    fn load(&self) -> Result<Option<Vec<u8>>, SvsmReqError>;

    /// Persist the given blob.
    ///
    /// Implementations should overwrite any prior content atomically when
    /// the backend supports it.
    fn save(&self, blob: &[u8]) -> Result<(), SvsmReqError>;
}

// ============================================================
// StaticBufStore — in-CVM static buffer
// ============================================================

const STATIC_BUF_CAPACITY: usize = 4096;

#[derive(Debug)]
struct StaticBuf {
    buf: [u8; STATIC_BUF_CAPACITY],
    len: usize,
    valid: bool,
}

/// In-CVM static buffer. Survives warm reboots within a single CVM
/// lifetime; zeroed on cold boot. Intended for development, testing,
/// and bring-up scenarios where no durable backing store is available.
#[derive(Debug)]
pub struct StaticBufStore {
    inner: SpinLock<StaticBuf>,
}

impl StaticBufStore {
    /// Create an empty store. Suitable for declaring as a `static`.
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(StaticBuf {
                buf: [0u8; STATIC_BUF_CAPACITY],
                len: 0,
                valid: false,
            }),
        }
    }

    /// Storage capacity in bytes.
    pub const fn capacity(&self) -> usize {
        STATIC_BUF_CAPACITY
    }
}

impl Default for StaticBufStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SealedBlobStore for StaticBufStore {
    fn load(&self) -> Result<Option<Vec<u8>>, SvsmReqError> {
        let g = self.inner.lock();
        if g.valid && g.len > 0 {
            Ok(Some(g.buf[..g.len].to_vec()))
        } else {
            Ok(None)
        }
    }

    fn save(&self, blob: &[u8]) -> Result<(), SvsmReqError> {
        if blob.len() > STATIC_BUF_CAPACITY {
            log::error!(
                "StaticBufStore::save — blob {} exceeds capacity {}",
                blob.len(),
                STATIC_BUF_CAPACITY
            );
            return Err(SvsmReqError::invalid_request());
        }
        let mut g = self.inner.lock();
        g.buf[..blob.len()].copy_from_slice(blob);
        g.len = blob.len();
        g.valid = true;
        Ok(())
    }
}

// ============================================================
// IgvmVarStore — stub for future IGVM variable backend
// ============================================================

/// IGVM variable-backed store. Reserved for the production path; the
/// load/save plumbing through the IGVM variable interface is not yet
/// implemented in this tree.
#[derive(Debug)]
pub struct IgvmVarStore;

impl IgvmVarStore {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for IgvmVarStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SealedBlobStore for IgvmVarStore {
    fn load(&self) -> Result<Option<Vec<u8>>, SvsmReqError> {
        log::debug!("IgvmVarStore::load — not yet implemented, returning empty");
        Ok(None)
    }

    fn save(&self, _blob: &[u8]) -> Result<(), SvsmReqError> {
        log::warn!("IgvmVarStore::save — not yet implemented, silently dropped");
        Ok(())
    }
}

// ============================================================
// VsockHostStore — AF_VSOCK to a host-side persistence helper
// ============================================================

/// VSOCK-backed store. Persists the sealed blob via a host-side helper
/// reachable over AF_VSOCK. The two ports separate the load and save
/// directions so that the helper can implement them as independent
/// services if desired.
#[cfg(feature = "vsock")]
#[derive(Debug)]
pub struct VsockHostStore {
    pub cid: u32,
    pub load_port: u32,
    pub save_port: u32,
}

#[cfg(feature = "vsock")]
impl VsockHostStore {
    /// Default VSOCK ports: 9997 for load, 9998 for save.
    pub const DEFAULT_LOAD_PORT: u32 = 9997;
    pub const DEFAULT_SAVE_PORT: u32 = 9998;

    pub const fn new(cid: u32, load_port: u32, save_port: u32) -> Self {
        Self {
            cid,
            load_port,
            save_port,
        }
    }
}

#[cfg(feature = "vsock")]
impl SealedBlobStore for VsockHostStore {
    fn load(&self) -> Result<Option<Vec<u8>>, SvsmReqError> {
        // TODO: open AF_VSOCK(cid, load_port), read framed blob.
        log::debug!(
            "VsockHostStore::load(cid={}, port={}) — not yet wired",
            self.cid,
            self.load_port
        );
        Ok(None)
    }

    fn save(&self, blob: &[u8]) -> Result<(), SvsmReqError> {
        // TODO: open AF_VSOCK(cid, save_port), write framed blob.
        log::debug!(
            "VsockHostStore::save(cid={}, port={}, {} bytes) — not yet wired",
            self.cid,
            self.save_port,
            blob.len()
        );
        Ok(())
    }
}
