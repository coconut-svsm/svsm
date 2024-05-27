use crate::address::VirtAddr;
use crate::error::SvsmError;
use crate::mm::alloc::{allocate_pages, free_page, get_order, AllocError, MAX_ORDER};
use crate::mm::PAGE_SIZE;
use core::borrow;
use core::marker::PhantomData;
use core::mem::{self, ManuallyDrop, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr;
use core::slice;

/// An abstraction, similar to a `Box`, for types that need to be allocated
/// using page allocator directly. This is useful for data structures and
/// types that need to reside on full pages, and which might also require raw
/// access to the underlying bytes.
#[derive(Debug)]
pub struct PageBox<T> {
    raw: RawPageBox,
    _phantom: PhantomData<T>,
}

impl<T> PageBox<T> {
    // Compile time checks - we cannot guarantee a better alignment than a
    // page in the general case and we do not handle zero-sized types.
    const ALIGN_OK: () = assert!(mem::align_of::<T>() <= PAGE_SIZE);
    const SIZE_OK: () = assert!(mem::size_of::<T>() > 0);

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
        let len = pages.as_raw().size();
        // SAFETY: the RawPageBox abstraction must return a valid pointer and
        // length as part of its invariants.
        unsafe { pages.as_raw_mut().as_mut_ptr().write_bytes(0, len) };
        Ok(pages)
    }

    /// Allocates enough pages to hold a `T`, but does not initialize them.
    pub fn try_new_uninit() -> Result<PageBox<MaybeUninit<T>>, SvsmError> {
        #[allow(clippy::let_unit_value)]
        {
            let _ = Self::ALIGN_OK;
            let _ = Self::SIZE_OK;
        }

        let order = get_order(mem::size_of::<T>());
        if order >= MAX_ORDER {
            return Err(SvsmError::Alloc(AllocError::OutOfMemory));
        }

        let raw = RawPageBox::new(order)?;
        // SAFETY: we made sure that the `RawPageBox` order is large enough.
        unsafe { Ok(PageBox::from_raw(raw)) }
    }

    /// Creates a new [`PageBox`] from a previously allocated [`RawPageBox`].
    ///
    /// # Safety
    ///
    /// The caller must ensure that the [`RawPageBox`] owns enough memory to
    /// store a `T`.
    #[inline]
    pub const unsafe fn from_raw(raw: RawPageBox) -> Self {
        Self {
            raw,
            _phantom: PhantomData,
        }
    }

    /// Obtains a reference to the inner [`RawPageBox`].
    #[inline]
    pub const fn as_raw(&self) -> &RawPageBox {
        &self.raw
    }

    /// Obtains a mutable reference to the inner [`RawPageBox`].
    #[inline]
    pub fn as_raw_mut(&mut self) -> &mut RawPageBox {
        &mut self.raw
    }

    pub fn leak<'a>(b: Self) -> &'a mut T {
        let ptr = ManuallyDrop::new(b).raw.as_mut_ptr().cast();
        unsafe { &mut *ptr }
    }
}

impl<T> PageBox<MaybeUninit<T>> {
    /// Transforms a [`PageBox<MaybeUninit<T>>`] into a [`PageBox<T>`].
    ///
    /// # Safety
    ///
    /// See the safety requirements for [`MaybeUninit::assume_init()`].
    pub unsafe fn assume_init(self) -> PageBox<T> {
        let order = self.raw.order;
        let leaked = PageBox::leak(self);
        let addr = VirtAddr::from(ptr::from_mut(leaked));
        PageBox::from_raw(RawPageBox::from_raw(addr, order))
    }
}

impl<T> Drop for PageBox<T> {
    fn drop(&mut self) {
        let ptr = self.as_raw_mut().as_mut_ptr().cast::<T>();
        unsafe { ptr::drop_in_place(ptr) };
    }
}

impl<T> Deref for PageBox<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: this is part of the invariants of this type, as it must
        // hold a pointer to valid memory for the given `T`.
        unsafe { &*self.raw.as_ptr().cast() }
    }
}

impl<T> DerefMut for PageBox<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: this is part of the invariants of this type, as it must
        // hold a pointer to valid memory for the given `T`.
        unsafe { &mut *self.raw.as_mut_ptr().cast() }
    }
}

impl<T> borrow::Borrow<T> for PageBox<T> {
    #[inline]
    fn borrow(&self) -> &T {
        // SAFETY: this is part of the invariants of this type, as it must
        // hold a pointer to valid memory for the given `T`.
        unsafe { &*self.raw.as_ptr().cast() }
    }
}

impl<T> borrow::BorrowMut<T> for PageBox<T> {
    #[inline]
    fn borrow_mut(&mut self) -> &mut T {
        // SAFETY: this is part of the invariants of this type, as it must
        // hold a pointer to valid memory for the given `T`.
        unsafe { &mut *self.raw.as_mut_ptr().cast() }
    }
}

impl<T> AsRef<T> for PageBox<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        // SAFETY: this is part of the invariants of this type, as it must
        // hold a pointer to valid memory for the given `T`.
        unsafe { &*self.raw.as_ptr().cast() }
    }
}

impl<T> AsMut<T> for PageBox<T> {
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        // SAFETY: this is part of the invariants of this type, as it must
        // hold a pointer to valid memory for the given `T`.
        unsafe { &mut *self.raw.as_mut_ptr().cast() }
    }
}

/// The raw contents of a [`PageBox`], allowing low level access to the
/// underlying memory.
#[derive(Debug)]
pub struct RawPageBox {
    addr: VirtAddr,
    order: usize,
}

impl RawPageBox {
    /// Allocates pages with the given order. The memory will be freed when
    /// this struct is dropped.
    #[inline]
    pub fn new(order: usize) -> Result<Self, SvsmError> {
        let addr = allocate_pages(order)?;
        Ok(Self { addr, order })
    }

    /// Creates a new [`RawPageBox`] from a page address and a page order.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `addr` was obtained from the page allocator
    /// and that it is valid, and that `order` corresponds to that page's order.
    const unsafe fn from_raw(addr: VirtAddr, order: usize) -> Self {
        Self { addr, order }
    }

    /// The byte length of the owned memory
    #[inline]
    pub const fn size(&self) -> usize {
        PAGE_SIZE << self.order
    }

    /// Gets the [`VirtAddr`] of the underlying memory.
    #[inline]
    pub const fn vaddr(&self) -> VirtAddr {
        self.addr
    }

    /// Gets a pointer to the underlying memory.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.vaddr().as_ptr()
    }

    /// Gets a mutable pointer to the underlying memory.
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.vaddr().as_mut_ptr()
    }

    /// Reinterprets the underlying memory as a byte slice of the appropriate size.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the underlying memory is initialized.
    #[inline]
    pub unsafe fn as_slice(&self) -> &[u8] {
        let ptr = self.addr.as_ptr();
        slice::from_raw_parts(ptr, self.size())
    }

    /// Reinterprets the underlying memory as a mutable byte slice of the
    /// appropriate size.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the underlying memory is initialized.
    #[inline]
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        let ptr = self.addr.as_mut_ptr();
        slice::from_raw_parts_mut(ptr, self.size())
    }
}

impl Drop for RawPageBox {
    fn drop(&mut self) {
        free_page(self.addr)
    }
}
