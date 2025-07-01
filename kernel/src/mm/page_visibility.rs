// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use core::mem::MaybeUninit;
use core::ops::Deref;
use core::ptr::NonNull;

use crate::address::VirtAddr;
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::mem::{unsafe_copy_bytes, write_bytes};
use crate::cpu::percpu::this_cpu;
use crate::error::SvsmError;
use crate::mm::validate::{
    valid_bitmap_clear_valid_4k, valid_bitmap_set_valid_4k, valid_bitmap_valid_addr,
};
use crate::mm::{virt_to_phys, PageBox};
use crate::platform::{PageStateChangeOp, PageValidateOp, SVSM_PLATFORM};
use crate::protocols::errors::SvsmReqError;
use crate::types::{PageSize, PAGE_SIZE};
use crate::utils::MemoryRegion;

use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

/// Makes a virtual page shared by revoking its validation, updating the
/// page state, and modifying the page tables accordingly.
///
/// # Arguments
///
/// * `vaddr` - The virtual address of the page to be made shared.
///
/// # Safety
///
/// Converting the memory at `vaddr` must be safe within Rust's memory model.
/// Notably any objects at `vaddr` must tolerate unsynchronized writes of any
/// bit pattern.  In addition, the caller must take responsibility for
/// returning a page to the private state if it is ever freed.
unsafe fn make_page_shared(vaddr: VirtAddr) -> Result<(), SvsmError> {
    // Revoke page validation before changing page state.
    // SAFETY: the caller verifies that the memory range is safe to convert.
    unsafe {
        SVSM_PLATFORM.validate_virtual_page_range(
            MemoryRegion::new(vaddr, PAGE_SIZE),
            PageValidateOp::Invalidate,
        )?;
    }
    let paddr = virt_to_phys(vaddr);
    if valid_bitmap_valid_addr(paddr) {
        valid_bitmap_clear_valid_4k(paddr);
    }

    // Ask the hypervisor to make the page shared.
    SVSM_PLATFORM.page_state_change(
        MemoryRegion::new(paddr, PAGE_SIZE),
        PageSize::Regular,
        PageStateChangeOp::Shared,
    )?;

    // Update the page tables to map the page as shared.
    this_cpu()
        .get_pgtable()
        .set_shared_4k(vaddr)
        .expect("Failed to remap shared page in page tables");
    flush_tlb_global_sync();

    Ok(())
}

/// Makes a virtual page private by updating the page tables, modifying the
/// page state, and revalidating the page.
///
/// # Arguments
///
/// * `vaddr` - The virtual address of the page to be made private.
///
/// # Safety
///
/// Converting the memory at `vaddr` must be safe within Rust's memory model.
/// No outstanding references to the page may exist.
unsafe fn make_page_private(vaddr: VirtAddr) -> Result<(), SvsmError> {
    // Update the page tables to map the page as private.
    this_cpu().get_pgtable().set_encrypted_4k(vaddr)?;
    flush_tlb_global_sync();

    // Ask the hypervisor to make the page private.
    let paddr = virt_to_phys(vaddr);
    SVSM_PLATFORM.page_state_change(
        MemoryRegion::new(paddr, PAGE_SIZE),
        PageSize::Regular,
        PageStateChangeOp::Private,
    )?;

    // Validate the page now that it is private again.
    // SAFETY: the caller verifies that the memory range is safe to convert.
    unsafe {
        SVSM_PLATFORM.validate_virtual_page_range(
            MemoryRegion::new(vaddr, PAGE_SIZE),
            PageValidateOp::Validate,
        )?;
    }
    if valid_bitmap_valid_addr(paddr) {
        valid_bitmap_set_valid_4k(paddr);
    }

    Ok(())
}

/// SharedBox is a safe wrapper around memory pages shared with the host.
pub struct SharedBox<T> {
    ptr: NonNull<T>,
}

impl<T: FromZeros> SharedBox<T> {
    /// Allocate some memory and share it with the host.
    pub fn try_new_zeroed() -> Result<Self, SvsmError> {
        let page_box = PageBox::<MaybeUninit<T>>::try_new_zeroed()?;
        let vaddr = page_box.vaddr();

        let ptr = NonNull::from(PageBox::leak(page_box)).cast::<T>();

        for offset in (0..core::mem::size_of::<T>()).step_by(PAGE_SIZE) {
            let r1 = unsafe { make_page_shared(vaddr + offset) };
            if let Err(e1) = r1 {
                for off in (0..offset).step_by(PAGE_SIZE) {
                    // SAFETY: we previously marked this page as shared in this same function.
                    let r2 = unsafe { make_page_private(vaddr + off) };
                    if let Err(e2) = r2 {
                        panic!(
                            "Failed to restore page visibility ({e2:?}) after allocation failure"
                        );
                    }
                }
                // SAFETY: we previously allocated these pages in this same function
                let _ = unsafe { PageBox::from_raw(ptr) };
                return Err(e1);
            }
        }

        Ok(Self { ptr })
    }
}

impl<T> SharedBox<T> {
    /// Returns the virtual address of the memory.
    pub fn addr(&self) -> VirtAddr {
        VirtAddr::from(self.ptr.as_ptr())
    }

    /// Read the currently stored value into `out`.
    pub fn read_into(&self, out: &mut T)
    where
        T: FromBytes + Copy,
    {
        // SAFETY: `self.ptr` is valid. Any bitpattern is valid for `T`.
        unsafe {
            unsafe_copy_bytes(self.ptr.as_ptr(), out, 1);
        }
    }

    /// Share `value` with the host.
    pub fn write_from(&mut self, value: &T)
    where
        T: Copy + IntoBytes + Immutable,
    {
        // SAFETY: `self.ptr` is valid. Value can be represented as a byte slice.
        unsafe {
            unsafe_copy_bytes(value, self.ptr.as_ptr(), 1);
        }
    }

    /// Leak the memory.
    pub fn leak(self) -> NonNull<T> {
        let ptr = self.ptr;
        core::mem::forget(self);
        ptr
    }

    // Gets the address of the inner pointer
    pub fn ptr_ref(&self) -> *const *const T {
        // We are casting a `*const NonNull<T>` to a `*const *const T`.
        // The cast is valid because `NonNull<T>` is transparent over
        // `*mut T`, and `*mut T` has the same layout as `*const T`.
        (&raw const self.ptr).cast()
    }
}

impl<T, const N: usize> SharedBox<[T; N]> {
    /// Clear the first `n` elements.
    pub fn nclear(&mut self, n: usize) -> Result<(), SvsmReqError>
    where
        T: FromZeros,
    {
        if n > N {
            return Err(SvsmReqError::invalid_parameter());
        }

        // SAFETY: `self.ptr` is valid and we did a bounds check on `n`.
        unsafe {
            write_bytes(self.ptr.as_ptr().cast::<T>(), n, 0);
        }

        Ok(())
    }

    /// Fill up the `outbuf` slice provided with bytes from data
    pub fn copy_to_slice(&self, outbuf: &mut [T]) -> Result<(), SvsmReqError>
    where
        T: FromBytes + Copy,
    {
        if outbuf.len() > N {
            return Err(SvsmReqError::invalid_parameter());
        }

        // SAFETY: `self.ptr` is valid.
        unsafe {
            unsafe_copy_bytes(self.ptr.as_ptr().cast(), outbuf.as_mut_ptr(), outbuf.len());
        }

        Ok(())
    }
}

impl<T: FromBytes + Sync> Deref for SharedBox<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        // SAFETY: ptr pointing to valid memory is part of this type's
        // invariant. The target is Sync, so there cannot be any data
        // races, and it is FromBytes, so it has no invalid
        // representations.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T: FromBytes + Sync> AsRef<T> for SharedBox<T> {
    fn as_ref(&self) -> &T {
        self
    }
}

unsafe impl<T> Send for SharedBox<T> where T: Send {}
unsafe impl<T> Sync for SharedBox<T> where T: Sync {}

impl<T> Drop for SharedBox<T> {
    fn drop(&mut self) {
        // Re-encrypt the pages.
        let res = (0..size_of::<Self>())
            .step_by(PAGE_SIZE)
            .try_for_each(|offset| unsafe { make_page_private(self.addr() + offset) });

        // If re-encrypting was successful free the memory otherwise leak it.
        if res.is_ok() {
            drop(unsafe { PageBox::from_raw(self.ptr.cast::<MaybeUninit<T>>()) });
        } else {
            log::error!("failed to set pages to encrypted. Memory leak!");
        }
    }
}

impl<T> core::fmt::Debug for SharedBox<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedBox").finish_non_exhaustive()
    }
}
