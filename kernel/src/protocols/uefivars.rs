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

use core::slice::from_raw_parts_mut;

use virtfw_varstore::mm::core::core_request;
use virtfw_varstore::store::EfiVarStore;

use crate::address::{Address, PhysAddr};
use crate::locking::SpinLock;
use crate::mm::{valid_phys_address, PerCPUPageMappingGuard};
use crate::protocols::errors::SvsmReqError;
use crate::protocols::RequestParams;

const SVSM_UEFI_MM_QUERY: u32 = 1;
const SVSM_UEFI_MM_SETUP: u32 = 2;
const SVSM_UEFI_MM_RESET: u32 = 3;
const SVSM_UEFI_MM_REQUEST: u32 = 4;

struct MmBuffer {
    addr: u64,
    size: usize,
}

impl MmBuffer {
    const fn new() -> Self {
        Self { addr: 0, size: 0 }
    }
}

static STORE: SpinLock<EfiVarStore> = SpinLock::new(EfiVarStore::new());
static BUFFER: SpinLock<MmBuffer> = SpinLock::new(MmBuffer::new());

// check if the protocol is supported
fn uefi_mm_query(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let flags = 0; // no feature flags yet.
    params.rcx = flags;
    Ok(())
}

// setup communication buffer
fn uefi_mm_setup(params: &RequestParams) -> Result<(), SvsmReqError> {
    let addr = params.rcx;
    let size = params.rdx;

    // check buffer parameters
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

    // save buffer parameters
    log::debug!("uefi mm buffer: 0x{addr:x} +0x{size:x}");
    let mut buffer = BUFFER.lock();
    buffer.addr = addr;
    buffer.size = size as usize;

    Ok(())
}

// reset protocol
fn uefi_mm_reset(_params: &RequestParams) -> Result<(), SvsmReqError> {
    let mut buffer = BUFFER.lock();
    buffer.addr = 0;
    buffer.size = 0;

    Ok(())
}

// process uefi mm request in communication buffer
fn uefi_mm_request(_params: &RequestParams) -> Result<(), SvsmReqError> {
    let buffer = BUFFER.lock();
    let mut store = STORE.lock();

    // check buffer parameters
    let paddr = PhysAddr::from(buffer.addr);
    if paddr.is_null() {
        return Err(SvsmReqError::invalid_parameter());
    }
    if !valid_phys_address(paddr) {
        return Err(SvsmReqError::invalid_address());
    }
    if paddr.page_offset() != 0 {
        return Err(SvsmReqError::invalid_address());
    }
    if buffer.size == 0 {
        return Err(SvsmReqError::invalid_parameter());
    }

    // map buffer
    let start = paddr.page_align();
    let end = (paddr + buffer.size).page_align_up();
    let guard = PerCPUPageMappingGuard::create(start, end, 0)?;
    let vaddr = guard.virt_addr();

    // SAFETY: vaddr comes from a new mapped region.
    let buffer = unsafe { from_raw_parts_mut(vaddr.as_mut_ptr::<u8>(), buffer.size) };

    // process request
    core_request(&mut store, buffer);

    Ok(())
}

pub fn uefi_mm_protocol_request(
    request: u32,
    params: &mut RequestParams,
) -> Result<(), SvsmReqError> {
    match request {
        SVSM_UEFI_MM_QUERY => uefi_mm_query(params),
        SVSM_UEFI_MM_SETUP => uefi_mm_setup(params),
        SVSM_UEFI_MM_RESET => uefi_mm_reset(params),
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
