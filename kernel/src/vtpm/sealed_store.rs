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
    #[inline] // R1: avoid sret aggregate-return on Option<Vec<u8>>
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
    #[inline] // R1: avoid sret aggregate-return on Option<Vec<u8>>
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
    /// Wire format: the host helper hands the raw blob bytes as a single
    /// stream — no framing header. The guest reads until peer-EOF and
    /// returns whatever it got. `Ok(None)` is reserved for two cases:
    ///
    ///   1. The helper is not running (connect refused) — interpreted as
    ///      a cold boot with no prior state.
    ///   2. The helper accepted the connection but produced 0 bytes —
    ///      same interpretation.
    ///
    /// This matches a `socat VSOCK-LISTEN:<port> OPEN:<file>,rdonly`
    /// helper that exits with EOF once the file is fully drained.
    #[inline] // R1: avoid sret aggregate-return on Option<Vec<u8>>
    fn load(&self) -> Result<Option<Vec<u8>>, SvsmReqError> {
        use crate::io::Read;
        use crate::vsock::stream::VsockStream;

        let mut stream = match VsockStream::connect(self.load_port, self.cid) {
            Ok(s) => s,
            Err(e) => {
                log::debug!(
                    "VsockHostStore::load(cid={}, port={}) — connect failed ({:?}); treating as cold boot",
                    self.cid,
                    self.load_port,
                    e
                );
                return Ok(None);
            }
        };

        let mut out = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
                Err(e) => {
                    log::error!(
                        "VsockHostStore::load(cid={}, port={}) — read error: {:?}",
                        self.cid,
                        self.load_port,
                        e
                    );
                    return Err(SvsmReqError::invalid_request());
                }
            }
        }

        if out.is_empty() {
            log::debug!(
                "VsockHostStore::load(cid={}, port={}) — peer returned 0 bytes",
                self.cid,
                self.load_port
            );
            return Ok(None);
        }

        log::info!(
            "VsockHostStore::load(cid={}, port={}) — got {} bytes",
            self.cid,
            self.load_port,
            out.len()
        );
        Ok(Some(out))
    }

    /// Open a fresh connection to the save port, write the blob in full,
    /// and let `Drop` shut the stream down — the host helper sees EOF
    /// and commits the file. Atomicity is the helper's responsibility
    /// (a `socat OPEN:<file>,creat,trunc` pattern truncates on accept
    /// and writes the new payload before close).
    fn save(&self, blob: &[u8]) -> Result<(), SvsmReqError> {
        use crate::io::Write;
        use crate::vsock::stream::VsockStream;

        let mut stream = VsockStream::connect(self.save_port, self.cid).map_err(|e| {
            log::error!(
                "VsockHostStore::save(cid={}, port={}) — connect failed: {:?}",
                self.cid,
                self.save_port,
                e
            );
            SvsmReqError::invalid_request()
        })?;

        // virtio-vsock under SVSM's HAL requires each `share`d buffer be
        // <= PAGE_SIZE (see kernel/src/virtio/hal.rs). Pre-Tier-B blobs were
        // ~2.7 KB so the single-shot write worked; the 16 KB s_NV section now
        // pushes the blob past 4 KB, so we must chunk explicitly here.
        const SAVE_CHUNK: usize = 2048;
        let mut written = 0usize;
        while written < blob.len() {
            let end = core::cmp::min(blob.len(), written + SAVE_CHUNK);
            let n = stream.write(&blob[written..end]).map_err(|e| {
                log::error!(
                    "VsockHostStore::save(cid={}, port={}) — write error at {}/{}: {:?}",
                    self.cid,
                    self.save_port,
                    written,
                    blob.len(),
                    e
                );
                SvsmReqError::invalid_request()
            })?;
            if n == 0 {
                log::error!(
                    "VsockHostStore::save(cid={}, port={}) — write returned 0 at {}/{}",
                    self.cid,
                    self.save_port,
                    written,
                    blob.len()
                );
                return Err(SvsmReqError::invalid_request());
            }
            written += n;
        }

        log::info!(
            "VsockHostStore::save(cid={}, port={}) — wrote {} bytes",
            self.cid,
            self.save_port,
            blob.len()
        );
        Ok(())
    }
}
