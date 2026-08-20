// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Red Hat, Inc.

//! File buffer for the C `fopen`/`fread`/`fwrite`/… wrappers,
//! with optional persistent storage through [`StorageBackend`].
//!
//! [`CFileBuffer`] implements fseek/fread/fwrite over a byte buffer and
//! delegates load/save to a compile-time selected backend:
//! `CocoonFsBackend` persists data to a CocoonFS inode, while
//! `VolatileBackend` keeps data in memory only.
//!
//! When no data is found on the backing store (first boot, no CocoonFS
//! storage, or volatile backend), [`StorageBackend::load`] returns `None`
//! and `fopen("r+b")` returns NULL, matching standard C semantics for a
//! nonexistent file.

extern crate alloc;

use alloc::vec::Vec;
use zeroize::Zeroizing;

use crate::error::SvsmError;
use crate::fs::FsError;

pub trait StorageBackend: Sized {
    fn open(path: &str) -> Option<Self>;
    fn load(&self) -> Option<Zeroizing<Vec<u8>>>;
    fn save(&self, buf: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, SvsmError>;
}

#[cfg(feature = "persistence")]
mod backend {
    use super::*;
    use crate::persistence::{
        Inode, persistence_available, persistence_read_inode_sync, persistence_write_inode_sync,
    };

    use super::super::TpmInode;

    pub struct CocoonFsBackend {
        inode: u64,
    }

    impl StorageBackend for CocoonFsBackend {
        fn open(path: &str) -> Option<Self> {
            match path {
                // "NVChip" is the only file opened by the TCG TPM reference
                // implementation when built with FILE_BACKED_NV=YES (NVMem.c).
                "NVChip" => Some(Self {
                    inode: TpmInode::NvChip.inode(),
                }),
                _ => {
                    log::error!("fopen: unsupported file: {path}");
                    None
                }
            }
        }

        fn load(&self) -> Option<Zeroizing<Vec<u8>>> {
            if !persistence_available() {
                return None;
            }

            // Treat errors as fatal: retries are already exhausted inside
            // persistence_read_inode_sync(), and returning None would let
            // NVMem.c create an empty NV image and overwrite the valid
            // persistent state, destroying TPM keys and seeds.
            // load() is only called once at startup (via fopen), so the
            // panic would happen then or never.
            persistence_read_inode_sync(self.inode)
                .expect("CocoonFsBackend: failed to load NV inode")
        }

        fn save(&self, data: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, SvsmError> {
            if !persistence_available() {
                return Ok(data);
            }

            persistence_write_inode_sync(self.inode, data, true)
        }
    }

    pub type Backend = CocoonFsBackend;
}

#[cfg(not(feature = "persistence"))]
mod backend {
    use super::*;

    pub struct VolatileBackend;

    impl StorageBackend for VolatileBackend {
        fn open(_path: &str) -> Option<Self> {
            Some(VolatileBackend)
        }

        fn load(&self) -> Option<Zeroizing<Vec<u8>>> {
            None
        }

        fn save(&self, buf: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, SvsmError> {
            Ok(buf)
        }
    }

    pub type Backend = VolatileBackend;
}

pub struct CFileBuffer<B: StorageBackend> {
    buf: Option<Zeroizing<Vec<u8>>>,
    pos: usize,
    backend: B,
}

impl<B: StorageBackend> CFileBuffer<B> {
    fn buf(&self) -> Result<&Zeroizing<Vec<u8>>, SvsmError> {
        self.buf.as_ref().ok_or(FsError::BadHandle.into())
    }

    fn buf_mut(&mut self) -> Result<&mut Zeroizing<Vec<u8>>, SvsmError> {
        self.buf.as_mut().ok_or(FsError::BadHandle.into())
    }

    fn load(backend: B) -> Option<Self> {
        let buf = backend.load()?;
        Some(Self {
            buf: Some(buf),
            pos: 0,
            backend,
        })
    }

    fn create(backend: B) -> Self {
        Self {
            buf: Some(Zeroizing::new(Vec::new())),
            pos: 0,
            backend,
        }
    }

    pub fn save(&mut self) -> Result<(), SvsmError> {
        let buf = self
            .buf
            .take()
            .ok_or(SvsmError::FileSystem(FsError::BadHandle))?;

        self.buf = Some(self.backend.save(buf)?);

        Ok(())
    }

    pub fn fread(&mut self, dst: &mut [u8], element_size: usize) -> Result<usize, SvsmError> {
        let buf = self.buf()?;

        if self.pos >= buf.len() || element_size == 0 || dst.is_empty() {
            return Ok(0);
        }

        let available = buf.len() - self.pos;
        let n = dst.len().min(available);
        let n = n - (n % element_size);
        dst[..n].copy_from_slice(&buf[self.pos..self.pos + n]);
        self.pos += n;

        Ok(n / element_size)
    }

    pub fn fwrite(&mut self, src: &[u8], element_size: usize) -> Result<usize, SvsmError> {
        let pos = self.pos;
        let buf = self.buf_mut()?;

        if element_size == 0 || src.is_empty() {
            return Ok(0);
        }

        let n = src.len() - (src.len() % element_size);
        let Some(end) = pos.checked_add(n) else {
            return Ok(0);
        };
        if end > buf.len() {
            buf.resize(end, 0);
        }
        buf[pos..end].copy_from_slice(&src[..n]);
        self.pos = end;

        Ok(n / element_size)
    }

    pub fn fseek(&mut self, offset: isize, whence: i32) -> Result<usize, SvsmError> {
        let buf = self.buf()?;

        let base = match whence {
            0 => 0,         // SEEK_SET
            1 => self.pos,  // SEEK_CUR
            2 => buf.len(), // SEEK_END
            _ => return Err(SvsmError::InvalidParameter),
        };
        let pos = base
            .checked_add_signed(offset)
            .ok_or(SvsmError::InvalidParameter)?;
        self.pos = pos;
        Ok(pos)
    }

    pub fn ftell(&self) -> Result<usize, SvsmError> {
        self.buf()?;
        Ok(self.pos)
    }
}

pub type CFile = CFileBuffer<backend::Backend>;

impl CFile {
    pub fn fopen(path: &str, mode: &str) -> Option<Self> {
        let backend = backend::Backend::open(path)?;

        match mode {
            "r+b" => Self::load(backend),
            "w+b" | "w" => Some(Self::create(backend)),
            _ => {
                log::error!("fopen: unsupported mode: {mode}");
                None
            }
        }
    }
}
