// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Red Hat, Inc.
//
// Author: Gerd Hoffmann <kraxel@redhat.com,>

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
//! is implemented by the virtfw_varstore crate.  The later implements
//! the MM protocols needed to provide an UEFI variable store.

use core::mem::size_of;

use virtfw_varstore::mm::core::{core_request_dispatch, MmCoreHeader};
use virtfw_varstore::store::EfiVarStore;

use crate::address::{Address, PhysAddr};
use crate::locking::SpinLock;
use crate::mm::guestmem::{copy_slice_to_guest, read_bytes_from_guest, read_from_guest};
use crate::mm::valid_phys_address;
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;

const SVSM_UEFI_MM_REQUEST: u32 = 1;

static STORE: SpinLock<EfiVarStore> = SpinLock::new(EfiVarStore::new());

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
    if size == 0 {
        return Err(SvsmReqError::invalid_parameter());
    }
    Ok(())
}

// process uefi mm request in passed buffer
fn uefi_mm_request(params: &RequestParams) -> Result<(), SvsmReqError> {
    let addr = params.rcx;
    let size = params.rdx as usize;

    let mut store = STORE.lock();

    // check buffer parameters
    check_buffer(addr, size)?;
    log::debug!("uefi mm buffer: 0x{addr:x} +0x{size:x}");

    let paddr = PhysAddr::from(addr);
    let mmcore = read_from_guest::<MmCoreHeader>(paddr)?;
    let boffset = size_of::<MmCoreHeader>();
    let bsize = mmcore.size as usize;
    if boffset + bsize > size {
        return Err(SvsmReqError::invalid_parameter());
    }

    let req = read_bytes_from_guest(paddr + boffset, bsize)?;
    let rsp = core_request_dispatch(&mut store, &mmcore.guid, &req);
    if rsp.len() > bsize {
        // should not happen (add SvsmReqError::internal_error() ?)
        log::debug!("uefi mm: response buffer too big");
        return Err(SvsmReqError::invalid_request());
    }
    copy_slice_to_guest(&rsp, paddr + boffset)?;

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
    store.reset();

    // In case a TPM is present, shim's fallback.efi will setup efi
    // boot variables then reboot.  This is not going to work until we
    // have persistence support for the UEFI variable store.  So turn
    // off that behaviour for now (via EFI variable).
    store.quirk_disable_shim_reboot(true);

    Ok(())
}
