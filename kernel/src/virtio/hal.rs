// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Red Hat, Inc.
//
// Author: Oliver Steffen <osteffen@redhat.com>

extern crate alloc;
use crate::{locking::SpinLock, platform::SVSM_PLATFORM, types::PAGE_SHIFT};
use alloc::vec::Vec;
use core::{
    mem::{MaybeUninit, size_of},
    num::NonZeroUsize,
    ptr::{NonNull, addr_of},
};
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::{
    address::{PhysAddr, VirtAddr},
    mm::{page_visibility::*, *},
};

struct PageStore {
    pages: Vec<(PhysAddr, SharedBox<[u8]>)>,
}

impl PageStore {
    pub const fn new() -> Self {
        PageStore { pages: Vec::new() }
    }

    pub fn push(&mut self, pa: PhysAddr, shared_pages: SharedBox<[u8]>) {
        self.pages.push((pa, shared_pages));
    }

    pub fn pop(&mut self, pa: PhysAddr) -> Option<SharedBox<[u8]>> {
        if let Some(p) = self.pages.iter().position(|e| e.0 == pa) {
            Some(self.pages.remove(p).1)
        } else {
            None
        }
    }
}

static SHARED_MEM: SpinLock<PageStore> = SpinLock::new(PageStore::new());

#[derive(Debug)]
pub struct SvsmHal;

/// Implementation of virtio-drivers MMIO hardware abstraction for AMD SEV-SNP
/// in the Coconut-SVSM context. Due to missing #VC handler for MMIO, use ghcb exits
/// instead.
///
/// SAFETY: Complies with the safety requirements of the virtio_drivers::Hal trait.
unsafe impl virtio_drivers::Hal for SvsmHal {
    /// Allocates and zeroes the given number of contiguous physical pages of DMA memory for VirtIO
    /// use.
    fn dma_alloc(
        pages: usize,
        _direction: virtio_drivers::BufferDirection,
    ) -> (virtio_drivers::PhysAddr, NonNull<u8>) {
        let size = NonZeroUsize::new(pages << PAGE_SHIFT).unwrap();
        let shared_pages = SharedBox::try_new_slice(0u8, size).unwrap();

        let pa = virt_to_phys(shared_pages.addr());
        let p = NonNull::<u8>::new(shared_pages.addr().as_mut_ptr()).unwrap();

        SHARED_MEM.lock().push(pa, shared_pages);

        (pa.into(), p)
    }

    /// Deallocates the given contiguous physical DMA memory pages.
    ///
    /// # Safety
    ///
    /// The memory must have been allocated by `dma_alloc` on the same `Hal` implementation, and not
    /// yet deallocated. `pages` must be the same number passed to `dma_alloc` originally, and both
    /// `paddr` and `vaddr` must be the values returned by `dma_alloc`.
    unsafe fn dma_dealloc(
        paddr: virtio_drivers::PhysAddr,
        _vaddr: NonNull<u8>,
        pages: usize,
    ) -> i32 {
        let shared_pages = SHARED_MEM.lock().pop(paddr.into()).unwrap();
        debug_assert_eq!(shared_pages.len() >> PAGE_SHIFT, pages);
        0
    }

    /// Converts a physical address used for MMIO to a virtual address.
    /// NOT IMPLEMENTED - the cut-down virtio driver for SVSM does not use this.
    unsafe fn mmio_phys_to_virt(_paddr: virtio_drivers::PhysAddr, _size: usize) -> NonNull<u8> {
        unimplemented!()
    }

    /// Shares the given memory range with the device, and returns the physical address that the
    /// device can use to access it.
    ///
    /// # Safety
    ///
    /// The buffer must be a valid pointer to a non-empty memory range which will not be accessed by
    /// any other thread for the duration of this method call.
    unsafe fn share(
        buffer: NonNull<[u8]>,
        direction: virtio_drivers::BufferDirection,
    ) -> virtio_drivers::PhysAddr {
        let size = NonZeroUsize::new(buffer.len()).unwrap();
        let shared_pages = SharedBox::try_new_slice(0u8, size).unwrap();

        if direction == virtio_drivers::BufferDirection::DriverToDevice {
            let src = buffer.as_ptr().cast::<u8>();
            let dst = shared_pages.addr().as_mut_ptr::<u8>();

            // SAFETY: We demand a valid `buffer` from the caller (virtio-drivers crate).
            //         We assterted that `dst` can hold at least `buffer.len()`.
            unsafe {
                core::ptr::copy_nonoverlapping(src, dst, buffer.len());
            }
        }

        let pa = virt_to_phys(shared_pages.addr());
        SHARED_MEM.lock().push(pa, shared_pages);

        // return pa of shared page
        pa.into()
    }

    /// Unshares the given memory range from the device and (if necessary) copies it back to the
    /// original buffer.
    ///
    /// # Safety
    ///
    /// The buffer must be a valid pointer to a non-empty memory range which will not be accessed by
    /// any other thread for the duration of this method call. The `paddr` must be the value
    /// previously returned by the corresponding `share` call.
    unsafe fn unshare(
        paddr: virtio_drivers::PhysAddr,
        buffer: NonNull<[u8]>,
        direction: virtio_drivers::BufferDirection,
    ) {
        match SHARED_MEM.lock().pop(paddr.into()) {
            Some(shared_page) => {
                let vaddr = phys_to_virt(paddr.into());
                let va_from_shared = shared_page.addr();
                assert!(vaddr == va_from_shared);

                if direction == virtio_drivers::BufferDirection::DeviceToDriver {
                    let dst = buffer.as_ptr().cast::<u8>();
                    let src = vaddr.as_mut_ptr::<u8>();

                    // SAFETY: `src` is valid, since it is returned by `phys_to_virt ()`
                    //         We rely on the caller (=virtio driver) to supply a valid `buffer` and
                    //         a matchting `paddr`, which was returned by a prevous call to `share ()`.
                    //         Thus we can assume that `dst` is valid and that `src` holds `buffer.len()` bytes.
                    unsafe {
                        core::ptr::copy_nonoverlapping(src, dst, buffer.len());
                    }
                }
            }
            _ => {
                panic!("unshare: No shared page found at given pa");
            }
        }
        // implicit drop of share_page here.
    }

    /// Performs memory mapped read from location of `src`. `src` itself is not modified,
    /// the value is returned instead.
    ///
    /// The default implementation performs a regular volatile_read. This method is intended
    /// to be overwritten in case MMIO memory needs to be accessed in a special way (for example AMD SEV-SNP).
    ///
    /// # Safety
    ///
    /// `src` must be properly aligned and reside at a readable memory address.
    unsafe fn mmio_read<T: FromBytes + Immutable>(src: &T) -> T {
        let mut b = MaybeUninit::<T>::uninit();
        // SAFETY: We are trusting the caller (the virtio driver) to ensure `src` is a valid MMIO
        // address and that it is aligned properly. If SVSM_PLATFORM.mmio_read() doesn't fail
        // we can assume that all the bytes are read from the device.
        unsafe {
            // MaybeUninit::as_bytes_mut() can avoid this, but it's still
            // unstable. When it will be stabilized, we can simply use
            // `b.as_bytes_mut()` instead of creating `b_slice`.
            let b_slice = core::slice::from_raw_parts_mut(
                b.as_mut_ptr().cast::<MaybeUninit<u8>>(),
                size_of::<T>(),
            );
            SVSM_PLATFORM
                .mmio_read(VirtAddr::from(addr_of!(*src)), b_slice)
                .unwrap();
            b.assume_init()
        }
    }

    /// Performs memory mapped write of `value` to the location of `dst`.
    ///
    /// The default implementation performs a regular volatile_write. This method is intended
    /// to be overwritten in case MMIO memory needs to be accessed in a special way (for example AMD SEV-SNP).
    ///
    /// # Safety
    ///
    /// `dst` must be properly aligned and reside at a writable memory address.
    unsafe fn mmio_write<T: IntoBytes + Immutable>(dst: &mut T, v: T) {
        // SAFETY: We are trusting the caller (the virtio driver) to ensure validity of `paddr` and alignment of data.
        unsafe {
            SVSM_PLATFORM
                .mmio_write(VirtAddr::from(addr_of!(*dst)), v.as_bytes())
                .unwrap();
        }
    }
}
