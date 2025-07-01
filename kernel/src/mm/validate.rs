// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::PhysAddr;
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::PageBox;
use crate::utils::MemoryRegion;
use crate::utils::valid_bitmap::{ValidBitmap,bitmap_elems};
use core::ptr::NonNull;


static VALID_BITMAP: SpinLock<Option<ValidBitmap>> = SpinLock::new(None);

/// # Safety
///
/// The caller must ensure that the given bitmap pointer is valid.
pub unsafe fn init_valid_bitmap_ptr(region: MemoryRegion<PhysAddr>, raw: NonNull<u64>) {
    let len = bitmap_elems(region);
    let ptr = NonNull::slice_from_raw_parts(raw, len.get());
    let bitmap = unsafe { PageBox::from_raw(ptr) };
    *VALID_BITMAP.lock() = Some(ValidBitmap::new(region, bitmap));
}

pub fn init_valid_bitmap_alloc(region: MemoryRegion<PhysAddr>) -> Result<(), SvsmError> {
    let len = bitmap_elems(region);
    let bitmap = PageBox::try_new_slice(0u64, len)?;
    *VALID_BITMAP.lock() = Some(ValidBitmap::new(region, bitmap));

    Ok(())
}

pub fn migrate_valid_bitmap() -> Result<(), SvsmError> {
    let len = VALID_BITMAP.lock().as_ref().unwrap().region_len();
    let bitmap = PageBox::try_new_uninit_slice(len)?;

    // lock again here because allocator path also takes VALID_BITMAP.lock()
    VALID_BITMAP.lock().as_mut().unwrap().migrate(bitmap);
    Ok(())
}

pub fn validated_phys_addr(paddr: PhysAddr) -> bool {
    VALID_BITMAP
        .lock()
        .as_ref()
        .map(|vb| vb.is_valid_4k(paddr))
        .unwrap_or(false)
}

pub fn valid_bitmap_set_valid_4k(paddr: PhysAddr) {
    if let Some(vb) = VALID_BITMAP.lock().as_mut() {
        vb.set_valid_4k(paddr);
    }
}

pub fn valid_bitmap_clear_valid_4k(paddr: PhysAddr) {
    if let Some(vb) = VALID_BITMAP.lock().as_mut() {
        vb.clear_valid_4k(paddr);
    }
}

pub fn valid_bitmap_set_valid_2m(paddr: PhysAddr) {
    if let Some(vb) = VALID_BITMAP.lock().as_mut() {
        vb.set_valid_2m(paddr);
    }
}

pub fn valid_bitmap_clear_valid_2m(paddr: PhysAddr) {
    if let Some(vb) = VALID_BITMAP.lock().as_mut() {
        vb.clear_valid_2m(paddr);
    }
}

pub fn valid_bitmap_set_valid_range(paddr_begin: PhysAddr, paddr_end: PhysAddr) {
    if let Some(vb) = VALID_BITMAP.lock().as_mut() {
        vb.set_valid_range(paddr_begin, paddr_end);
    }
}

pub fn valid_bitmap_clear_valid_range(paddr_begin: PhysAddr, paddr_end: PhysAddr) {
    if let Some(vb) = VALID_BITMAP.lock().as_mut() {
        vb.clear_valid_range(paddr_begin, paddr_end);
    }
}

pub fn valid_bitmap_addr() -> PhysAddr {
    VALID_BITMAP.lock().as_ref().unwrap().bitmap_addr()
}

pub fn valid_bitmap_valid_addr(paddr: PhysAddr) -> bool {
    VALID_BITMAP
        .lock()
        .as_ref()
        .map(|vb| vb.check_addr(paddr))
        .unwrap_or(false)
}
