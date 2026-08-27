// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Red Hat, Inc.
//
// Author: Gerd Hoffmann <kraxel@redhat.com>

//! UEFI MM protocol implementation
//!
//! Process MM communication requests from edk2 firmware.
//!
//! Usually this request serialization format is used by edk2 for
//! communication between normal mode and management mode (MM for
//! short).
//!
//! This SVSM protocol is a thin wrapper to allow edk2 firmware send
//! those requests to the SVSM instead.  The actual request processing
//! is implemented by the virtfw_varstore crate.  The latter implements
//! the MM protocols needed to provide an UEFI variable store.

extern crate alloc;
use alloc::vec::Vec;
use bitfield_struct::bitfield;
use core::mem::size_of;
use zerocopy::{Immutable, IntoBytes};

use virtfw_libefi::efivar::ids::PK;
use virtfw_varstore::mm::core::{MmCoreHeader, core_request_dispatch};
use virtfw_varstore::store::EfiVarStore;

use crate::address::{Address, PhysAddr};
use crate::locking::SpinLock;
use crate::mm::guestmem::{copy_slice_to_guest, read_bytes_from_guest, read_from_guest};
use crate::mm::valid_phys_address;
#[cfg(feature = "persistence")]
use crate::persistence::persistence_available;
use crate::protocols::RequestParams;
use crate::protocols::errors::SvsmReqError;

const SVSM_UEFI_MM_REQUEST: u32 = 1;

pub const UEFI_MM_PROTOCOL_VERSION_MIN: u32 = 1;
pub const UEFI_MM_PROTOCOL_VERSION_MAX: u32 = 1;

// current edk2 uses 64k
const UEFI_MM_BUFFER_LIMIT: usize = 256 * 1024;

static STORE: SpinLock<EfiVarStore> = SpinLock::new(EfiVarStore::new());

#[cfg(feature = "persistence")]
mod persistance {
    extern crate alloc;
    use alloc::vec::Vec;

    use virtfw_varstore::fs::FsIndexParser;
    use virtfw_varstore::store::EfiVarStore;

    use crate::error::SvsmError;
    use crate::persistence::{
        Inode, InodeNamespace, persistence_enumerate_inodes_sync, persistence_read_inode_sync,
        persistence_unlink_inode_sync, persistence_write_inode_sync,
    };

    struct UefiInode {
        inode: u32,
    }

    impl UefiInode {
        fn new(inode: u32) -> Self {
            Self { inode }
        }
    }

    impl From<UefiInode> for u32 {
        fn from(val: UefiInode) -> u32 {
            val.inode
        }
    }

    impl Inode for UefiInode {
        const NAMESPACE: InodeNamespace = InodeNamespace::Uefi;
    }

    pub(crate) fn write(store: &mut EfiVarStore) -> Result<(), SvsmError> {
        if !store.fs_is_modified() {
            return Ok(());
        }
        let Ok(index) = store.fs_make_index() else {
            return Err(SvsmError::InvalidFormat);
        };
        for (entry, name) in FsIndexParser::new(&index) {
            if let Some(data) = store.fs_get_variable(&entry, &name) {
                let inode = UefiInode::new(entry.inode());
                let vec: Vec<u8> = data.into();
                persistence_write_inode_sync(inode.inode(), vec.into(), true)?;
            }
        }

        let inode = UefiInode::new(store.fs_inode_index());
        persistence_write_inode_sync(inode.inode(), index.into(), true)?;
        store.fs_clear_modified();
        Ok(())
    }

    pub(crate) fn read(store: &mut EfiVarStore) -> Result<(), SvsmError> {
        let inode = UefiInode::new(store.fs_inode_index());
        let index_opt = persistence_read_inode_sync(inode.inode())?;
        let Some(index) = index_opt else {
            return Ok(());
        };
        for (entry, name) in FsIndexParser::new(&index) {
            let inode = UefiInode::new(entry.inode());
            if let Some(data) = persistence_read_inode_sync(inode.inode())? {
                store.fs_set_variable(&entry, &name, &data);
            }
        }
        Ok(())
    }

    pub(crate) fn garbage_collect(store: &mut EfiVarStore) -> Result<(), SvsmError> {
        let min = UefiInode::new(0);
        let max = UefiInode::new(0xffff_ffff);
        let range = min.inode()..=max.inode();

        let mut stale: Vec<UefiInode> = Vec::new();
        let _ = persistence_enumerate_inodes_sync::<()>(range, &mut |inode| {
            let uefi_nr: u32 = (inode & 0xffff_ffff).try_into().unwrap();
            if !store.fs_inode_is_used(uefi_nr) {
                stale.push(UefiInode::new(uefi_nr));
            }
            None
        });
        for inode in stale {
            persistence_unlink_inode_sync(inode.inode(), true)?;
        }
        Ok(())
    }
}

fn check_buffer(addr: u64, size: usize) -> Result<(), SvsmReqError> {
    let paddr = PhysAddr::from(addr);
    if paddr.is_null() {
        return Err(SvsmReqError::invalid_parameter());
    }
    if !valid_phys_address(paddr) {
        return Err(SvsmReqError::invalid_address());
    }
    if paddr.page_offset() != 0 {
        return Err(SvsmReqError::invalid_address());
    }
    if size < size_of::<MmCoreHeader>() {
        return Err(SvsmReqError::invalid_parameter());
    }
    if size > UEFI_MM_BUFFER_LIMIT {
        return Err(SvsmReqError::invalid_parameter());
    }
    Ok(())
}

// process uefi mm request in passed buffer
fn uefi_mm_request(params: &RequestParams) -> Result<(), SvsmReqError> {
    let addr = params.rcx;
    let size = params.rdx as usize;

    // check buffer parameters
    check_buffer(addr, size)?;
    log::debug!("uefi mm buffer: 0x{addr:x} +0x{size:x}");

    let paddr = PhysAddr::from(addr);
    let mmcore = read_from_guest::<MmCoreHeader>(paddr)?;
    let boffset = size_of::<MmCoreHeader>();
    let bsize = mmcore.size as usize;
    if bsize > size - boffset {
        return Err(SvsmReqError::invalid_parameter());
    }

    let mut store = STORE.lock();
    let req = read_bytes_from_guest(paddr + boffset, bsize)?;
    let rsp = core_request_dispatch(&mut store, &mmcore.guid, &req);
    assert!(rsp.len() <= bsize);
    copy_slice_to_guest(&rsp, paddr + boffset)?;

    #[cfg(feature = "persistence")]
    if persistence_available() {
        self::persistance::write(&mut store)?;
    }

    Ok(())
}

pub fn uefi_mm_protocol_request(
    request: u32,
    params: &mut RequestParams,
) -> Result<(), SvsmReqError> {
    match request {
        SVSM_UEFI_MM_REQUEST => uefi_mm_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}

pub fn uefi_mm_protocol_init() -> Result<(), SvsmReqError> {
    let mut store = STORE.lock();

    #[cfg(feature = "persistence")]
    if persistence_available() {
        log::info!("loading uefi variable store");
        self::persistance::read(&mut store)?;
        self::persistance::garbage_collect(&mut store)?;
    }

    #[cfg(feature = "secureboot")]
    if store.get_setup_mode() {
        // hard coded configuration for now.
        log::info!("enroll secure boot certificates");
        store.enroll_pk_mgmt();
        store.enroll_kek_microsoft();
        store.enroll_db_microsoft_uefi();
        store.enroll_dbx_native();
    }

    // In case a TPM is present, shim's fallback.efi will setup
    // efi boot variables then reboot.  This is not going to work
    // unless there is a persistence UEFI variable store.  So turn
    // off that behaviour if needed.
    #[cfg(feature = "persistence")]
    let need_quirk = !persistence_available();
    #[cfg(not(feature = "persistence"))]
    let need_quirk = true;
    if need_quirk {
        store.quirk_disable_shim_reboot(true);
    }

    store.reset();
    Ok(())
}

#[bitfield(u32)]
#[derive(IntoBytes, Immutable)]
pub struct UefiMmManifestFlags {
    // non-volatile uefi variables are written to persistent storage
    pub persistent_nv_vars: bool,
    // secure boot is enabled
    pub secureboot_enabled: bool,
    // secure boot databases ('db' + 'dbx') can be updated by the
    // guest (assuming proper pkcs7 signature of course).
    // This should only be set in case secure boot is enabled.
    pub secureboot_db_update: bool,

    #[bits(29)]
    _reserved: u32,
}

#[derive(IntoBytes, Immutable)]
#[repr(C, packed)]
struct UefiMmManifest {
    pub version: u32,
    pub flags: UefiMmManifestFlags,
}

pub fn uefi_mm_get_manifest() -> Result<Vec<u8>, SvsmReqError> {
    let store = STORE.lock();

    let pk = store.get(&PK.into());
    let sb = pk.is_ok();

    let flags = UefiMmManifestFlags::new()
        .with_persistent_nv_vars(false)
        .with_secureboot_enabled(sb)
        .with_secureboot_db_update(false);
    let manifest = UefiMmManifest { version: 0, flags };

    Ok(manifest.as_bytes().to_vec())
}
