// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2024 SUSE
//
// Author: Carlos López <carlos.lopez@suse.com>
use super::alloc::{allocate_pages, free_page, get_order, MAX_ORDER};
use super::PAGE_SIZE;
use crate::address::VirtAddr;
use crate::error::SvsmError;
use core::borrow;
use core::marker::PhantomData;
use core::mem::{self, ManuallyDrop, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

/// An abstraction, similar to a `Box`, for types that need to be allocated
/// using page allocator directly.
///
/// Constructing a [`PageBox`] is very similar to constructing a regular `Box`:
///
/// ```no_run
/// # use svsm::mm::PageBox;
/// let p = PageBox::try_new([0u8; 4096])?;
/// # Ok::<(), svsm::error::SvsmError>(())
/// ```
///
/// The type guarantees that the allocated memory will have a minimum alignment
/// of the page size, and that memory will be valid until it is dropped.
///
/// The type does not support zero sized types nor unsized types. On the other
/// hand, it is able to check at compile time that the contained `T` can fit in
/// a page allocation with the required alignment. For example, the following
/// will not build because its size exceeds the maximum page order:
///
/// ```compile_fail
/// # use svsm::mm::PageBox;
/// let p = PageBox::try_new([0u8; 0x80000])?;
/// # Ok::<(), svsm::error::SvsmError>(())
/// ```
#[derive(Debug)]
#[repr(transparent)]
pub struct PageBox<T> {
    ptr: NonNull<T>,
    _phantom: PhantomData<T>,
}

impl<T> PageBox<T> {
    /// Allocates enough pages to hold a `T`, initializing them with the given value.
    pub fn try_new(x: T) -> Result<Self, SvsmError> {
        let mut pages = PageBox::<T>::try_new_uninit()?;
        // SAFETY: the pointer returned by MaybeUninit::as_mut_ptr() must be
        // valid as part of its invariants. We can assume memory is
        // initialized after writing to it.
        unsafe {
            MaybeUninit::as_mut_ptr(&mut pages).write(x);
            Ok(pages.assume_init())
        }
    }

    /// Allocates enough pages to hold a `T`, and zeroes them out.
    pub fn try_new_zeroed() -> Result<PageBox<MaybeUninit<T>>, SvsmError> {
        let mut pages = Self::try_new_uninit()?;
        unsafe { MaybeUninit::as_mut_ptr(&mut pages).write_bytes(0, 1) };
        Ok(pages)
    }

    /// Gets the page order required for an allocation to hold a `T`. It also
    /// checks that the size and alignment requirements of the type can be
    /// serviced.
    const fn get_order() -> usize {
        // We cannot guarantee a better alignment than a page in the general
        // case and we do not handle zero-sized types, or types that are larger
        // than the maximum order page size. We can check all of this at compile
        // time because we do not suppport unsized types.
        assert!(mem::size_of::<T>() > 0);
        assert!(mem::align_of::<T>() <= PAGE_SIZE);
        let order = get_order(mem::size_of::<T>());
        assert!(order < MAX_ORDER);
        order
    }

    /// Allocates enough pages to hold a `T`, but does not initialize them.
    pub fn try_new_uninit() -> Result<PageBox<MaybeUninit<T>>, SvsmError> {
        let order = const { Self::get_order() };
        let addr = NonNull::new(allocate_pages(order)?.as_mut_ptr()).unwrap();
        unsafe { Ok(PageBox::from_raw(addr)) }
    }

    /// Create a [`PageBox`] from a previous allocation of the same type.
    ///
    /// # Safety
    ///
    /// The provided pointer must come from a previous use of [`PageBox`]
    /// (likely through [`leak()`](PageBox::leak), and must not be aliased.
    #[inline]
    pub const unsafe fn from_raw(ptr: NonNull<T>) -> Self {
        Self {
            ptr,
            _phantom: PhantomData,
        }
    }

    /// Consumes and leaks the `PageBox`, returning a mutable reference. The
    /// contents will never be freed unless the mutable reference is
    /// converted back to a `PageBox` via [`from_raw()`](PageBox::from_raw).
    pub fn leak<'a>(b: Self) -> &'a mut T {
        unsafe { ManuallyDrop::new(b).ptr.as_mut() }
    }

    /// Returns the virtual address of this allocation.
    #[inline]
    pub fn vaddr(&self) -> VirtAddr {
        VirtAddr::from(self.ptr.as_ptr())
    }
}

impl<T> PageBox<MaybeUninit<T>> {
    /// Transforms a [`PageBox<MaybeUninit<T>>`] into a [`PageBox<T>`].
    ///
    /// # Safety
    ///
    /// See the safety requirements for [`MaybeUninit::assume_init()`].
    pub unsafe fn assume_init(self) -> PageBox<T> {
        let leaked = PageBox::leak(self).assume_init_mut();
        let raw = NonNull::from(leaked);
        PageBox::from_raw(raw)
    }
}

impl<T> Deref for PageBox<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: this is part of the invariants of this type, as it must
        // hold a pointer to valid memory for the given `T`.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> DerefMut for PageBox<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: this is part of the invariants of this type, as it must
        // hold a pointer to valid memory for the given `T`.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T> borrow::Borrow<T> for PageBox<T> {
    #[inline]
    fn borrow(&self) -> &T {
        // SAFETY: this is part of the invariants of this type, as it must
        // hold a pointer to valid memory for the given `T`.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> borrow::BorrowMut<T> for PageBox<T> {
    #[inline]
    fn borrow_mut(&mut self) -> &mut T {
        // SAFETY: this is part of the invariants of this type, as it must
        // hold a pointer to valid memory for the given `T`.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T> AsRef<T> for PageBox<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        // SAFETY: this is part of the invariants of this type, as it must
        // hold a pointer to valid memory for the given `T`.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> AsMut<T> for PageBox<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        // SAFETY: this is part of the invariants of this type, as it must
        // hold a pointer to valid memory for the given `T`.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T> Drop for PageBox<T> {
    fn drop(&mut self) {
        let ptr = self.ptr.as_ptr();
        unsafe { ptr.drop_in_place() };
        free_page(VirtAddr::from(ptr));
    }
}

/// `TryBox` is `Send` if `T` is `Send` because the data it
/// references via its internal pointer is unaliased.
unsafe impl<T: Send> Send for PageBox<T> {}

/// `TryBox` is `Sync` if `T` is `Sync` because the data it
/// references via its internal pointer is unaliased.
unsafe impl<T: Sync> Sync for PageBox<T> {}
