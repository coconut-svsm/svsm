// SPDX-License-Identifier: MIT

//! Fake HAL implementation for tests.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(missing_docs)]

use crate::{BufferDirection, Hal, PhysAddr, PAGE_SIZE};
use alloc::alloc::{alloc_zeroed, dealloc, handle_alloc_error};
use core::{
    alloc::Layout,
    ptr::{self, NonNull},
};
use zerocopy::FromZeros;

#[derive(Debug)]
pub struct FakeHal;

/// Fake HAL implementation for use in unit tests.
///
/// SAFETY: Follows the safety requirements outlined for the Hal trait.
unsafe impl Hal for FakeHal {
    fn dma_alloc(pages: usize, _direction: BufferDirection) -> (PhysAddr, NonNull<u8>) {
        assert_ne!(pages, 0);
        let layout = Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap();
        // SAFETY: Safe because the size and alignment of the layout are non-zero.
        let ptr = unsafe { alloc_zeroed(layout) };
        if let Some(ptr) = NonNull::new(ptr) {
            (ptr.as_ptr() as PhysAddr, ptr)
        } else {
            handle_alloc_error(layout);
        }
    }

    /// # Safety
    ///
    /// Caller must ensure vaddr was returned by a previous call to dma_alloc and the
    /// number of pages is the same.
    unsafe fn dma_dealloc(_paddr: PhysAddr, vaddr: NonNull<u8>, pages: usize) -> i32 {
        assert_ne!(pages, 0);
        let layout = Layout::from_size_align(pages * PAGE_SIZE, PAGE_SIZE).unwrap();
        // SAFETY: Safe because the layout is the same as was used when the memory was allocated by
        // `dma_alloc` above.
        unsafe {
            dealloc(vaddr.as_ptr(), layout);
        }
        0
    }

    /// # Safety
    ///
    /// Caller must ensure paddr is a valid MMIO region of the given size.
    unsafe fn mmio_phys_to_virt(paddr: PhysAddr, _size: usize) -> NonNull<u8> {
        NonNull::new(paddr as _).unwrap()
    }

    /// # Safety
    ///
    /// The buffer must be a valid pointer to a non-empty memory range which will not be accessed by
    /// any other thread for the duration of this method call.
    unsafe fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> PhysAddr {
        assert_ne!(buffer.len(), 0);
        // To ensure that the driver is handling and unsharing buffers properly, allocate a new
        // buffer and copy to it if appropriate.
        let mut shared_buffer = <[u8]>::new_box_zeroed_with_elems(buffer.len()).unwrap();
        if let BufferDirection::DriverToDevice | BufferDirection::Both = direction {
            // SAFETY: Safe because shared_buffer was allocated just above with the correct size
            unsafe {
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .copy_to(shared_buffer.as_mut_ptr(), buffer.len());
            }
        }
        let vaddr = Box::into_raw(shared_buffer) as *mut u8 as usize;
        // Nothing to do, as the host already has access to all memory.
        virt_to_phys(vaddr)
    }

    /// # Safety
    ///
    /// The buffer must be a valid pointer to a non-empty memory range which will not be accessed by
    /// any other thread for the duration of this method call. The `paddr` must be the value
    /// previously returned by the corresponding `share` call.
    unsafe fn unshare(paddr: PhysAddr, buffer: NonNull<[u8]>, direction: BufferDirection) {
        assert_ne!(buffer.len(), 0);
        assert_ne!(paddr, 0);
        let vaddr = phys_to_virt(paddr);
        // SAFETY: Caller has to ensure that paddr was returned by a matching call to share()
        // above.
        let shared_buffer = unsafe {
            Box::from_raw(ptr::slice_from_raw_parts_mut(
                vaddr as *mut u8,
                buffer.len(),
            ))
        };
        if let BufferDirection::DeviceToDriver | BufferDirection::Both = direction {
            // SAFETY: Caller has to ensure that paddr was returned by a matching call to share()
            // above.
            unsafe {
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .copy_from(shared_buffer.as_ptr(), buffer.len());
            }
        }
    }
}

fn virt_to_phys(vaddr: usize) -> PhysAddr {
    vaddr
}

fn phys_to_virt(paddr: PhysAddr) -> usize {
    paddr
}
