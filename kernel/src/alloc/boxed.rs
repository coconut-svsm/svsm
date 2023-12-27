// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 SUSE
//
// Author: Carlos López <carlos.lopez@suse.com>

//! The `TryBox<T>` type for heap allocation.
//!
//! [`TryBox<T>`], casually referred to as a 'box', provides the simplest form of
//! heap allocation in Rust. Boxes provide ownership for this allocation, and
//! drop their contents when they go out of scope. Boxes also ensure that they
//! never allocate more than `isize::MAX` bytes.
//!
//! This is a downstream version of `Box` with a stabilized allocator API,
//! supporting fallible allocations exclusively.

use core::alloc::Layout;
use core::any::Any;
use core::borrow;
use core::cmp::Ordering;
use core::fmt;
use core::mem;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::ptr::{self, NonNull};

use super::unique::Unique;
use super::{Allocator, TryAllocError};

/// A pointer type that uniquely owns a heap allocation of type `T`, generic
/// over any given allocator, and supporting only fallible allocations.
///
/// This is a downstream version of `Box` with a stabilized allocator API,
/// supporting fallible allocations exclusively.
pub struct TryBox<T: ?Sized, A: Allocator>(Unique<T>, A);

impl<T, A: Allocator> TryBox<T, A> {
    /// Allocates memory in the given allocator then places `x` into it,
    /// returning an error if the allocation fails
    ///
    /// This doesn't actually allocate if `T` is zero-sized.
    ///
    /// # Examples
    ///
    /// ```
    /// # use svsm::alloc::boxed::TryBox;
    /// use std::alloc::System;
    ///
    /// let five = TryBox::try_new_in(5, System)?;
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    #[inline]
    pub fn try_new_in(x: T, alloc: A) -> Result<Self, TryAllocError> {
        let mut boxed = Self::try_new_uninit_in(alloc)?;
        unsafe {
            boxed.as_mut_ptr().write(x);
            Ok(boxed.assume_init())
        }
    }

    /// Allocates memory in the given allocator then places `x` into it,
    /// returning an error if the allocation fails
    ///
    /// This doesn't actually allocate if `T` is zero-sized.
    ///
    /// # Examples
    ///
    /// ```
    /// # use svsm::alloc::boxed::TryBox;
    /// use std::alloc::System;
    ///
    /// let five = TryBox::try_new_in(5, System)?;
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    pub fn try_new_uninit_in(alloc: A) -> Result<TryBox<mem::MaybeUninit<T>, A>, TryAllocError> {
        let ptr = if mem::size_of::<T>() == 0 {
            NonNull::dangling()
        } else {
            let layout = Layout::new::<mem::MaybeUninit<T>>();
            alloc.allocate(layout)?.cast()
        };
        unsafe { Ok(TryBox::from_raw_in(ptr.as_ptr(), alloc)) }
    }

    /// Constructs a new `TryBox` with uninitialized contents, with the memory
    /// being filled with `0` bytes in the provided allocator.
    ///
    /// See [`MaybeUninit::zeroed`][zeroed] for examples of correct and incorrect usage
    /// of this method.
    ///
    /// # Examples
    ///
    /// ```
    /// # use svsm::alloc::boxed::TryBox;
    /// use std::alloc::System;
    ///
    /// let zero = TryBox::<u32, _>::try_new_zeroed_in(System)?;
    /// let zero = unsafe { zero.assume_init() };
    ///
    /// assert_eq!(*zero, 0);
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    ///
    /// [zeroed]: mem::MaybeUninit::zeroed
    pub fn try_new_zeroed_in(alloc: A) -> Result<TryBox<mem::MaybeUninit<T>, A>, TryAllocError> {
        let ptr = if mem::size_of::<T>() == 0 {
            NonNull::dangling()
        } else {
            let layout = Layout::new::<mem::MaybeUninit<T>>();
            alloc.allocate_zeroed(layout)?.cast()
        };
        unsafe { Ok(TryBox::from_raw_in(ptr.as_ptr(), alloc)) }
    }

    /// Constructs a new `Pin<TryBox<T, A>>`. If `T` does not implement
    /// [`Unpin`], then `x` will be pinned in memory and unable to be
    /// moved.
    ///
    /// Constructing and pinning of the `TryBox` can also be done in two
    /// steps: `TryBox::try_pin_in(x, alloc)` does the same as
    /// <code>[TryBox::into_pin]\([TryBox::try_new_in]\(x, alloc)?)</code>.
    /// Consider using [`into_pin`](TryBox::into_pin) if you already have a
    /// `TryBox<T, A>`, or if you want to construct a (pinned) `TryBox` in
    /// a different way than with [`TryBox::try_new_in`].
    pub fn try_pin_in(x: T, alloc: A) -> Result<Pin<Self>, TryAllocError>
    where
        A: 'static + Allocator,
    {
        let boxed = Self::try_new_in(x, alloc)?;
        Ok(Self::into_pin(boxed))
    }

    pub fn into_boxed_slice(boxed: Self) -> TryBox<[T], A> {
        let (raw, alloc) = TryBox::into_raw_with_allocator(boxed);
        unsafe { TryBox::from_raw_in(raw as *mut [T; 1], alloc) }
    }

    /// Consumes the `TryBox`, returning the wrapped value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use svsm::alloc::boxed::TryBox;
    ///
    /// use std::alloc::{Layout, System};
    ///
    /// let c = TryBox::try_new_in(5, System)?;
    ///
    /// assert_eq!(TryBox::into_inner(c), 5);
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    #[inline]
    pub fn into_inner(self) -> T {
        unsafe { self.0.as_ptr().read() }
    }
}

impl<T, A: Allocator> TryBox<mem::MaybeUninit<T>, A> {
    /// Converts to `TryBox<T, A>`.
    ///
    /// # Safety
    ///
    /// As with [`MaybeUninit::assume_init`],
    /// it is up to the caller to guarantee that the value
    /// really is in an initialized state.
    /// Calling this when the content is not yet fully initialized
    /// causes immediate undefined behavior.
    ///
    /// [`MaybeUninit::assume_init`]: mem::MaybeUninit::assume_init
    ///
    /// # Examples
    ///
    /// ```
    /// # use svsm::alloc::boxed::TryBox;
    /// use std::alloc::System;
    ///
    /// let mut five = TryBox::<u32, _>::try_new_uninit_in(System)?;
    ///
    /// let five = unsafe {
    ///     // Deferred initialization:
    ///     five.as_mut_ptr().write(5);
    ///
    ///     five.assume_init()
    /// };
    ///
    /// assert_eq!(*five, 5);
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    #[inline]
    pub unsafe fn assume_init(self) -> TryBox<T, A> {
        let (raw, alloc) = TryBox::into_raw_with_allocator(self);
        unsafe { TryBox::from_raw_in(raw as *mut T, alloc) }
    }

    /// Writes the value and converts to `TryBox<T, A>`.
    ///
    /// This method converts the box similarly to [`TryBox::assume_init`] but
    /// writes `value` into it before conversion thus guaranteeing safety.
    /// In some scenarios use of this method may improve performance because
    /// the compiler may be able to optimize copying from stack.
    ///
    /// # Examples
    ///
    /// ```
    /// # use svsm::alloc::boxed::TryBox;
    /// use std::alloc::System;
    ///
    /// let big_box = TryBox::<[usize; 1024], _>::try_new_uninit_in(System)?;
    ///
    /// let mut array = [0; 1024];
    /// for (i, place) in array.iter_mut().enumerate() {
    ///     *place = i;
    /// }
    ///
    /// // The optimizer may be able to elide this copy, so previous code writes
    /// // to heap directly.
    /// let big_box = TryBox::write(big_box, array);
    ///
    /// for (i, x) in big_box.iter().enumerate() {
    ///     assert_eq!(*x, i);
    /// }
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    #[inline]
    pub fn write(mut boxed: Self, value: T) -> TryBox<T, A> {
        unsafe {
            (*boxed).write(value);
            boxed.assume_init()
        }
    }
}

impl<T: ?Sized, A: Allocator> TryBox<T, A> {
    /// Constructs a box from a raw pointer in the given allocator.
    ///
    /// After calling this function, the raw pointer is owned by the
    /// resulting `TryBox`. Specifically, the `TryBox` destructor will call
    /// the destructor of `T` and free the allocated memory. For this
    /// to be safe, the memory must have been allocated in accordance
    /// with the memory layout used by `TryBox` .
    ///
    /// # Safety
    ///
    /// This function is unsafe because improper use may lead to
    /// memory problems. For example, a double-free may occur if the
    /// function is called twice on the same raw pointer.
    ///
    ///
    /// # Examples
    ///
    /// Recreate a `TryBox` which was previously converted to a raw pointer
    /// using [`TryBox::into_raw_with_allocator`]:
    /// ```
    /// # use svsm::alloc::boxed::TryBox;
    /// use std::alloc::System;
    ///
    /// let x = TryBox::try_new_in(5, System)?;
    /// let (ptr, alloc) = TryBox::into_raw_with_allocator(x);
    /// let x = unsafe { TryBox::from_raw_in(ptr, alloc) };
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    /// Manually create a `TryBox` from scratch by using the system allocator:
    /// ```
    /// # use svsm::alloc::{boxed::TryBox, Allocator};
    /// use std::alloc::{Layout, System};
    ///
    /// unsafe {
    ///     let ptr = System.allocate(Layout::new::<i32>())?.as_ptr() as *mut i32;
    ///     // In general .write is required to avoid attempting to destruct
    ///     // the (uninitialized) previous contents of `ptr`, though for this
    ///     // simple example `*ptr = 5` would have worked as well.
    ///     ptr.write(5);
    ///     let x = TryBox::from_raw_in(ptr, System);
    /// }
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    #[inline]
    pub unsafe fn from_raw_in(raw: *mut T, alloc: A) -> Self {
        Self(unsafe { Unique::new_unchecked(raw) }, alloc)
    }

    /// Consumes the `TryBox`, returning a wrapped raw pointer.
    ///
    /// The pointer will be properly aligned and non-null.
    ///
    /// After calling this function, the caller is responsible for the
    /// memory previously managed by the `TryBox`. In particular, the
    /// caller should properly destroy `T` and release the memory, taking
    /// into account the memory layout used by `TryBox`. The easiest way to
    /// do this is to convert the raw pointer back into a `TryBox` with the
    /// [`TryBox::from_raw_in`] function, allowing the `TryBox` destructor to perform
    /// the cleanup.
    ///
    /// Note: this is an associated function, which means that you have
    /// to call it as `TryBox::into_raw(b)` instead of `b.into_raw()`. This
    /// is so that there is no conflict with a method on the inner type.
    ///
    /// # Examples
    /// Converting the raw pointer back into a `TryBox` with [`TryBox::from_raw_in`]
    /// for automatic cleanup:
    /// ```
    /// # use svsm::alloc::boxed::TryBox;
    /// use std::alloc::System;
    ///
    /// let x = TryBox::try_new_in(String::from("Hello"), System)?;
    /// let ptr = TryBox::into_raw(x);
    /// let x = unsafe { TryBox::from_raw_in(ptr, System) };
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    /// Manual cleanup by explicitly running the destructor and deallocating
    /// the memory:
    /// ```
    /// # use svsm::alloc::{boxed::TryBox, Allocator};
    /// use std::alloc::{Layout, System};
    /// use std::ptr::{self, NonNull};
    ///
    /// let x = TryBox::try_new_in(String::from("Hello"), System)?;
    /// let p = TryBox::into_raw(x);
    /// unsafe {
    ///     ptr::drop_in_place(p);
    ///     let non_null = NonNull::new_unchecked(p);
    ///     System.deallocate(non_null.cast(), Layout::new::<String>());
    /// }
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    #[inline]
    pub fn into_raw(b: Self) -> *mut T {
        Self::into_raw_with_allocator(b).0
    }

    /// Consumes the `TryBox`, returning a wrapped raw pointer and the allocator.
    ///
    /// The pointer will be properly aligned and non-null.
    ///
    /// After calling this function, the caller is responsible for the
    /// memory previously managed by the `TryBox`. In particular, the
    /// caller should properly destroy `T` and release the memory, taking
    /// into account the memory layout used by `TryBox`. The easiest way to
    /// do this is to convert the raw pointer back into a `TryBox` with the
    /// [`TryBox::from_raw_in`] function, allowing the `TryBox` destructor to perform
    /// the cleanup.
    ///
    /// Note: this is an associated function, which means that you have
    /// to call it as `TryBox::into_raw_with_allocator(b)` instead of `b.into_raw_with_allocator()`. This
    /// is so that there is no conflict with a method on the inner type.
    ///
    /// # Examples
    /// Converting the raw pointer back into a `TryBox` with [`TryBox::from_raw_in`]
    /// for automatic cleanup:
    /// ```
    /// # use svsm::alloc::boxed::TryBox;
    /// use std::alloc::System;
    ///
    /// let x = TryBox::try_new_in(String::from("Hello"), System)?;
    /// let (ptr, alloc) = TryBox::into_raw_with_allocator(x);
    /// let x = unsafe { TryBox::from_raw_in(ptr, alloc) };
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    /// Manual cleanup by explicitly running the destructor and deallocating
    /// the memory:
    /// ```
    /// # use svsm::alloc::{boxed::TryBox, Allocator};
    ///
    /// use std::alloc::{Layout, System};
    /// use std::ptr::{self, NonNull};
    ///
    /// let x = TryBox::try_new_in(String::from("Hello"), System)?;
    /// let (ptr, alloc) = TryBox::into_raw_with_allocator(x);
    /// unsafe {
    ///     ptr::drop_in_place(ptr);
    ///     let non_null = NonNull::new_unchecked(ptr);
    ///     alloc.deallocate(non_null.cast(), Layout::new::<String>());
    /// }
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    #[inline]
    pub fn into_raw_with_allocator(b: Self) -> (*mut T, A) {
        let (leaked, alloc) = TryBox::into_unique(b);
        (leaked.as_ptr(), alloc)
    }

    #[inline]
    pub(super) fn into_unique(b: Self) -> (Unique<T>, A) {
        // TryBox is recognized as a "unique pointer" by Stacked Borrows, but internally it is a
        // raw pointer for the type system. Turning it directly into a raw pointer would not be
        // recognized as "releasing" the unique pointer to permit aliased raw accesses,
        // so all raw pointer methods have to go through `TryBox::leak`. Turning *that* to a raw pointer
        // behaves correctly.
        let alloc = unsafe { ptr::read(&b.1) };
        (Unique::from(Self::leak(b)), alloc)
    }

    /// Returns a reference to the underlying allocator.
    ///
    /// Note: this is an associated function, which means that you have
    /// to call it as `TryBox::allocator(&b)` instead of `b.allocator()`. This
    /// is so that there is no conflict with a method on the inner type.
    #[inline]
    pub const fn allocator(b: &Self) -> &A {
        &b.1
    }

    /// Consumes and leaks the `TryBox`, returning a mutable reference,
    /// `&'a mut T`. Note that the type `T` must outlive the chosen lifetime
    /// `'a`. If the type has only static references, or none at all, then this
    /// may be chosen to be `'static`.
    ///
    /// This function is mainly useful for data that lives for the remainder of
    /// the program's life. Dropping the returned reference will cause a memory
    /// leak. If this is not acceptable, the reference should first be wrapped
    /// with the [`TryBox::from_raw_in`] function producing a `TryBox`. This `TryBox` can
    /// then be dropped which will properly destroy `T` and release the
    /// allocated memory.
    ///
    /// Note: this is an associated function, which means that you have
    /// to call it as `TryBox::leak(b)` instead of `b.leak()`. This
    /// is so that there is no conflict with a method on the inner type.
    ///
    /// # Examples
    ///
    /// Simple usage:
    ///
    /// ```
    /// # use svsm::alloc::boxed::TryBox;
    /// use std::alloc::System;
    ///
    /// let x = TryBox::try_new_in(41, System)?;
    /// let static_ref: &'static mut usize = TryBox::leak(x);
    /// *static_ref += 1;
    /// assert_eq!(*static_ref, 42);
    ///
    /// // Deallocate
    /// let x = unsafe { TryBox::from_raw_in(static_ref, System) };
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    ///
    /// Unsized data:
    ///
    /// ```
    /// # use svsm::alloc::boxed::TryBox;
    /// use std::alloc::System;
    ///
    /// let x = TryBox::into_boxed_slice(TryBox::try_new_in(41, System)?);
    /// let static_ref = TryBox::leak(x);
    /// static_ref[0] = 4;
    /// assert_eq!(static_ref[0], 4);
    ///
    /// // Deallocate
    /// let x = unsafe { TryBox::from_raw_in(static_ref, System) };
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    #[inline]
    pub fn leak<'a>(b: Self) -> &'a mut T
    where
        A: 'a,
    {
        unsafe { &mut *mem::ManuallyDrop::new(b).0.as_ptr() }
    }

    /// Converts a `TryBox<T>` into a `Pin<TryBox<T>>`. If `T` does not implement [`Unpin`], then
    /// `*boxed` will be pinned in memory and unable to be moved.
    ///
    /// This conversion does not allocate on the heap and happens in place.
    ///
    /// This is also available via [`From`].
    ///
    /// Constructing and pinning a `TryBox` with <code>TryBox::into_pin([TryBox::try_new_in]\(x, alloc))</code>
    /// can also be written more concisely using <code>[TryBox::try_pin_in]\(x, alloc)</code>.
    /// This `into_pin` method is useful if you already have a `TryBox<T>`, or you are
    /// constructing a (pinned) `TryBox` in a different way than with [`TryBox::try_new_in`].
    ///
    /// # Notes
    ///
    /// It's not recommended that crates add an impl like `From<TryBox<T>> for Pin<T>`,
    /// as it'll introduce an ambiguity when calling `Pin::from`.
    pub fn into_pin(boxed: Self) -> Pin<Self>
    where
        A: 'static,
    {
        // It's not possible to move or replace the insides of a `Pin<Box<T>>`
        // when `T: !Unpin`, so it's safe to pin it directly without any
        // additional requirements.
        unsafe { Pin::new_unchecked(boxed) }
    }
}

impl<T: ?Sized, A: Allocator> Drop for TryBox<T, A> {
    #[inline]
    fn drop(&mut self) {
        let ptr = self.0;
        unsafe {
            let layout = Layout::for_value(ptr.as_ref());
            ptr.as_ptr().drop_in_place();
            if layout.size() != 0 {
                self.1.deallocate(From::from(ptr.cast()), layout);
            }
        }
    }
}

impl<T: ?Sized + Default, A: Allocator> TryBox<T, A> {
    /// Allocates memory in the given allocator and places the default value
    /// for `T` into it.
    #[inline]
    pub fn try_default_in(alloc: A) -> Result<Self, TryAllocError> {
        Self::try_new_in(T::default(), alloc)
    }
}

impl<T: ?Sized + Clone, A: Allocator + Clone> TryBox<T, A> {
    /// Returns a new `TryBox` with this box's contents. The new box is
    /// allocated with this box's allocator.
    pub fn try_clone(&self) -> Result<Self, TryAllocError> {
        let boxed = Self::try_new_uninit_in(self.1.clone())?;
        Ok(TryBox::write(boxed, unsafe { self.0.as_ref().clone() }))
    }
}

impl<T: ?Sized + Clone, A: Allocator> TryBox<T, A> {
    /// Returns a new `TryBox` with this box's contents. The new box is
    /// allocated with the given allocator.
    pub fn try_clone_in(&self, alloc: A) -> Result<Self, TryAllocError> {
        let boxed = Self::try_new_uninit_in(alloc)?;
        Ok(TryBox::write(boxed, unsafe { self.0.as_ref().clone() }))
    }
}

impl<T: ?Sized + PartialEq, A: Allocator> PartialEq for TryBox<T, A> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        PartialEq::eq(&**self, &**other)
    }
}

impl<T: ?Sized + PartialOrd, A: Allocator> PartialOrd for TryBox<T, A> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        PartialOrd::partial_cmp(&**self, &**other)
    }
    #[inline]
    fn lt(&self, other: &Self) -> bool {
        PartialOrd::lt(&**self, &**other)
    }
    #[inline]
    fn le(&self, other: &Self) -> bool {
        PartialOrd::le(&**self, &**other)
    }
    #[inline]
    fn ge(&self, other: &Self) -> bool {
        PartialOrd::ge(&**self, &**other)
    }
    #[inline]
    fn gt(&self, other: &Self) -> bool {
        PartialOrd::gt(&**self, &**other)
    }
}

impl<T: ?Sized + Ord, A: Allocator> Ord for TryBox<T, A> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(&**self, &**other)
    }
}

impl<T: ?Sized + Eq, A: Allocator> Eq for TryBox<T, A> {}

impl<T: ?Sized, A: Allocator> From<TryBox<T, A>> for Pin<TryBox<T, A>>
where
    A: 'static,
{
    /// Converts a `TryBox<T>` into a `Pin<TryBox<T>>`. If `T` does not implement [`Unpin`], then
    /// `*boxed` will be pinned in memory and unable to be moved.
    ///
    /// This conversion does not allocate on the heap and happens in place.
    ///
    /// This is also available via [`TryBox::into_pin`].
    ///
    /// Constructing and pinning a `TryBox` with <code><Pin<TryBox\<T>>>::from([TryBox::try_new_in]\(x, alloc)?)</code>
    /// can also be written more concisely using <code>[TryBox::try_pin_in]\(x, alloc)?</code>.
    /// This `From` implementation is useful if you already have a `TryBox<T>`, or you are
    /// constructing a (pinned) `TryBox` in a different way than with [`TryBox::try_new_in`].
    fn from(boxed: TryBox<T, A>) -> Self {
        TryBox::into_pin(boxed)
    }
}

/// Upcast a [`TryBox`] to a `dyn trait` object. Normally this macro would not
/// be necessary, as trait coercion via [`CoerceUnsized`](core::ops::CoerceUnsized)
/// would transparently convert any `TryBox<T, A>` to `TryBox<dyn Any, A>`,
/// but since `CoerceUnsized` is not stable, we need an explicit macro.
///
/// ```
/// use std::alloc::System;
/// use svsm::alloc::boxed::TryBox;
/// use svsm::trybox_upcast;
///
/// trait MyTrait {}
/// impl MyTrait for usize {}
///
/// let boxed = TryBox::try_new_in(5usize, System)?;
/// let v: TryBox<dyn MyTrait, _> = trybox_upcast!(boxed, MyTrait);
/// # Ok::<(), svsm::alloc::TryAllocError>(())
/// ```
///
/// Upcasting to a trait that `T` does not implement does not work:
///
/// ```compile_fail
/// use std::alloc::System;
/// use svsm::trybox_upcast;
/// use svsm::alloc::boxed::TryBox;
///
/// trait MyTrait {}
///
/// let boxed = TryBox::try_new_in(5usize, System)?;
/// let v: TryBox<dyn MyTrait, _> = trybox_upcast!(boxed, MyTrait);
/// # Ok::<(), svsm::alloc::TryAllocError>(())
/// ```
#[macro_export]
macro_rules! trybox_upcast {
    ($boxed:expr, $bound:tt $(+ $others:tt)*) => {{
        let (ptr, alloc) = TryBox::into_raw_with_allocator($boxed);
        unsafe { TryBox::from_raw_in(ptr as *mut (dyn $bound $(+ $others)*), alloc) }
    }}
}

impl<A: Allocator> TryBox<dyn Any, A> {
    /// Attempt to downcast the box to a concrete type.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::alloc::System;
    /// use std::any::Any;
    /// use svsm::alloc::{boxed::TryBox, Allocator};
    /// use svsm::trybox_upcast;
    ///
    /// fn print_if_string<A: Allocator>(value: TryBox<dyn Any, A>) {
    ///     if let Ok(string) = value.downcast::<String>() {
    ///         println!("String ({}): {}", string.len(), string);
    ///     }
    /// }
    ///
    /// let my_string = "Hello World".to_string();
    /// print_if_string(trybox_upcast!(TryBox::try_new_in(my_string, System)?, Any));
    /// print_if_string(trybox_upcast!(TryBox::try_new_in(0i8, System)?, Any));
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    #[inline]
    pub fn downcast<T: Any>(self) -> Result<TryBox<T, A>, Self> {
        if self.is::<T>() {
            unsafe { Ok(self.downcast_unchecked::<T>()) }
        } else {
            Err(self)
        }
    }

    /// Downcasts the box to a concrete type.
    ///
    /// For a safe alternative see [`downcast`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::alloc::System;
    /// use std::any::Any;
    /// use svsm::alloc::boxed::TryBox;
    /// use svsm::trybox_upcast;
    ///
    /// let x = trybox_upcast!(TryBox::try_new_in(1_usize, System)?, Any);
    ///
    /// unsafe {
    ///     assert_eq!(*x.downcast_unchecked::<usize>(), 1);
    /// }
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    ///
    /// # Safety
    ///
    /// The contained value must be of type `T`. Calling this method
    /// with the incorrect type is *undefined behavior*.
    ///
    /// [`downcast`]: Self::downcast
    #[inline]
    pub unsafe fn downcast_unchecked<T: Any>(self) -> TryBox<T, A> {
        debug_assert!(self.is::<T>());
        unsafe {
            let (raw, alloc): (*mut dyn Any, _) = TryBox::into_raw_with_allocator(self);
            TryBox::from_raw_in(raw as *mut T, alloc)
        }
    }
}

impl<A: Allocator> TryBox<dyn Any + Send, A> {
    /// Attempt to downcast the box to a concrete type.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::alloc::System;
    /// use std::any::Any;
    /// use svsm::alloc::boxed::TryBox;
    /// use svsm::trybox_upcast;
    ///
    /// fn print_if_string(value: TryBox<dyn Any + Send, System>) {
    ///     if let Ok(string) = value.downcast::<String>() {
    ///         println!("String ({}): {}", string.len(), string);
    ///     }
    /// }
    ///
    /// let my_string = "Hello World".to_string();
    /// print_if_string(trybox_upcast!(
    ///     TryBox::try_new_in(my_string, System)?,
    ///     Any + Send
    /// ));
    /// print_if_string(trybox_upcast!(TryBox::try_new_in(0i8, System)?, Any + Send));
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    #[inline]
    pub fn downcast<T: Any>(self) -> Result<TryBox<T, A>, Self> {
        if self.is::<T>() {
            unsafe { Ok(self.downcast_unchecked::<T>()) }
        } else {
            Err(self)
        }
    }

    /// Downcasts the box to a concrete type.
    ///
    /// For a safe alternative see [`downcast`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::alloc::System;
    /// use std::any::Any;
    /// use svsm::alloc::boxed::TryBox;
    /// use svsm::trybox_upcast;
    ///
    /// let x = trybox_upcast!(TryBox::try_new_in(1_usize, System)?, Any + Send);
    ///
    /// unsafe {
    ///     assert_eq!(*x.downcast_unchecked::<usize>(), 1);
    /// }
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    ///
    /// # Safety
    ///
    /// The contained value must be of type `T`. Calling this method
    /// with the incorrect type is *undefined behavior*.
    ///
    /// [`downcast`]: Self::downcast
    #[inline]
    pub unsafe fn downcast_unchecked<T: Any>(self) -> TryBox<T, A> {
        debug_assert!(self.is::<T>());
        unsafe {
            let (raw, alloc): (*mut (dyn Any + Send), _) = TryBox::into_raw_with_allocator(self);
            TryBox::from_raw_in(raw as *mut T, alloc)
        }
    }
}

impl<A: Allocator> TryBox<dyn Any + Send + Sync, A> {
    /// Attempt to downcast the box to a concrete type.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::alloc::System;
    /// use std::any::Any;
    /// use svsm::alloc::boxed::TryBox;
    /// use svsm::trybox_upcast;
    ///
    /// fn print_if_string(value: TryBox<dyn Any + Send + Sync, System>) {
    ///     if let Ok(string) = value.downcast::<String>() {
    ///         println!("String ({}): {}", string.len(), string);
    ///     }
    /// }
    ///
    /// let my_string = "Hello World".to_string();
    /// print_if_string(trybox_upcast!(
    ///     TryBox::try_new_in(my_string, System)?,
    ///     Any + Send + Sync
    /// ));
    /// print_if_string(trybox_upcast!(
    ///     TryBox::try_new_in(0i8, System)?,
    ///     Any + Send + Sync
    /// ));
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    #[inline]
    pub fn downcast<T: Any>(self) -> Result<TryBox<T, A>, Self> {
        if self.is::<T>() {
            unsafe { Ok(self.downcast_unchecked::<T>()) }
        } else {
            Err(self)
        }
    }

    /// Downcasts the box to a concrete type.
    ///
    /// For a safe alternative see [`downcast`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::alloc::System;
    /// use std::any::Any;
    /// use svsm::alloc::boxed::TryBox;
    /// use svsm::trybox_upcast;
    ///
    /// let x = trybox_upcast!(TryBox::try_new_in(1_usize, System)?, Any + Send + Sync);
    ///
    /// unsafe {
    ///     assert_eq!(*x.downcast_unchecked::<usize>(), 1);
    /// }
    /// # Ok::<(), svsm::alloc::TryAllocError>(())
    /// ```
    ///
    /// # Safety
    ///
    /// The contained value must be of type `T`. Calling this method
    /// with the incorrect type is *undefined behavior*.
    ///
    /// [`downcast`]: Self::downcast
    #[inline]
    pub unsafe fn downcast_unchecked<T: Any>(self) -> TryBox<T, A> {
        debug_assert!(self.is::<T>());
        unsafe {
            let (raw, alloc): (*mut (dyn Any + Send + Sync), _) =
                TryBox::into_raw_with_allocator(self);
            TryBox::from_raw_in(raw as *mut T, alloc)
        }
    }
}

impl<T: fmt::Display + ?Sized, A: Allocator> fmt::Display for TryBox<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl<T: fmt::Debug + ?Sized, A: Allocator> fmt::Debug for TryBox<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl<T: ?Sized, A: Allocator> fmt::Pointer for TryBox<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // It's not possible to extract the inner Uniq directly from the Box,
        // instead we cast it to a *const which aliases the Unique
        let ptr: *const T = &**self;
        fmt::Pointer::fmt(&ptr, f)
    }
}

impl<T: ?Sized, A: Allocator> Deref for TryBox<T, A> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.0.as_ptr() }
    }
}

impl<T: ?Sized, A: Allocator> DerefMut for TryBox<T, A> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.0.as_ptr() }
    }
}

impl<T: ?Sized, A: Allocator> borrow::Borrow<T> for TryBox<T, A> {
    fn borrow(&self) -> &T {
        unsafe { &*self.0.as_ptr() }
    }
}

impl<T: ?Sized, A: Allocator> borrow::BorrowMut<T> for TryBox<T, A> {
    fn borrow_mut(&mut self) -> &mut T {
        unsafe { &mut *self.0.as_ptr() }
    }
}

impl<T: ?Sized, A: Allocator> AsRef<T> for TryBox<T, A> {
    fn as_ref(&self) -> &T {
        unsafe { &*self.0.as_ptr() }
    }
}

impl<T: ?Sized, A: Allocator> AsMut<T> for TryBox<T, A> {
    fn as_mut(&mut self) -> &mut T {
        unsafe { &mut *self.0.as_ptr() }
    }
}

/* Nota bene
 *
 *  We could have chosen not to add this impl, and instead have written a
 *  function of Pin<Box<T>> to Pin<T>. Such a function would not be sound,
 *  because Box<T> implements Unpin even when T does not, as a result of
 *  this impl.
 *
 *  We chose this API instead of the alternative for a few reasons:
 *      - Logically, it is helpful to understand pinning in regard to the
 *        memory region being pointed to. For this reason none of the
 *        standard library pointer types support projecting through a pin
 *        (Box<T> is the only pointer type in std for which this would be
 *        safe.)
 *      - It is in practice very useful to have Box<T> be unconditionally
 *        Unpin because of trait objects, for which the structural auto
 *        trait functionality does not apply (e.g., Box<dyn Foo> would
 *        otherwise not be Unpin).
 *
 *  Another type with the same semantics as Box but only a conditional
 *  implementation of `Unpin` (where `T: Unpin`) would be valid/safe, and
 *  could have a method to project a Pin<T> from it.
 */
impl<T: ?Sized, A: Allocator> Unpin for TryBox<T, A> where A: 'static {}
