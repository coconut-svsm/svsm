// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use core::mem::MaybeUninit;
use core::ptr::NonNull;

use crate::address::VirtAddr;
use crate::cpu::flush_tlb_global_sync;
use crate::cpu::mem::{copy_bytes, write_bytes};
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

use zerocopy::{FromBytes, FromZeros};

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
pub unsafe fn make_page_shared(vaddr: VirtAddr) -> Result<(), SvsmError> {
    // Revoke page validation before changing page state.
    SVSM_PLATFORM.validate_virtual_page_range(
        MemoryRegion::new(vaddr, PAGE_SIZE),
        PageValidateOp::Invalidate,
    )?;
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
pub unsafe fn make_page_private(vaddr: VirtAddr) -> Result<(), SvsmError> {
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
    SVSM_PLATFORM.validate_virtual_page_range(
        MemoryRegion::new(vaddr, PAGE_SIZE),
        PageValidateOp::Validate,
    )?;
    if valid_bitmap_valid_addr(paddr) {
        valid_bitmap_set_valid_4k(paddr);
    }

    Ok(())
}

/// SharedBox is a safe wrapper around memory pages shared with the host.
pub struct SharedBox<T> {
    ptr: NonNull<T>,
}

impl<T> SharedBox<T> {
    /// Allocate some memory and share it with the host.
    pub fn try_new_zeroed() -> Result<Self, SvsmError> {
        let page_box = PageBox::<MaybeUninit<T>>::try_new_zeroed()?;
        let vaddr = page_box.vaddr();

        let ptr = NonNull::from(PageBox::leak(page_box)).cast::<T>();

        for offset in (0..core::mem::size_of::<T>()).step_by(PAGE_SIZE) {
            unsafe {
                make_page_shared(vaddr + offset)?;
            }
        }

        Ok(Self { ptr })
    }

    /// Returns the virtual address of the memory.
    pub fn addr(&self) -> VirtAddr {
        VirtAddr::from(self.ptr.as_ptr())
    }

    /// Read the currently stored value into `out`.
    pub fn read_into(&self, out: &mut T)
    where
        T: FromBytes + Copy,
    {
        unsafe {
            // SAFETY: `self.ptr` is valid. Any bitpattern is valid for `T`.
            copy_bytes(
                self.ptr.as_ptr() as usize,
                out as *const T as usize,
                size_of::<T>(),
            );
        }
    }

    /// Share `value` with the host.
    pub fn write_from(&mut self, value: &T)
    where
        T: Copy,
    {
        unsafe {
            // SAFETY: `self.ptr` is valid..
            copy_bytes(
                value as *const T as usize,
                self.ptr.as_ptr() as usize,
                size_of::<T>(),
            );
        }
    }

    /// Leak the memory.
    pub fn leak(self) -> NonNull<T> {
        let ptr = self.ptr;
        core::mem::forget(self);
        ptr
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

        unsafe {
            // SAFETY: `self.ptr` is valid and we did a bounds check on `n`.
            write_bytes(self.ptr.as_ptr() as usize, size_of::<T>() * n, 0);
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

        let size = core::mem::size_of_val(outbuf);
        unsafe {
            // SAFETY: `self.ptr` is valid.
            copy_bytes(
                self.ptr.as_ptr() as usize,
                outbuf.as_mut_ptr() as usize,
                size,
            );
        }

        Ok(())
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
