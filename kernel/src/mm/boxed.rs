// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com>

use super::alloc::{SvsmAllocator, ALLOCATOR};
use crate::alloc::boxed::TryBox;
use crate::alloc::TryAllocError;
use crate::error::SvsmError;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};

impl From<TryAllocError> for SvsmError {
    fn from(err: TryAllocError) -> Self {
        SvsmError::TryAlloc(err)
    }
}

/// See the documentation for [`trybox_upcast`](crate::trybox_upcast).
#[macro_export]
macro_rules! globalbox_upcast {
    ($boxed:expr, $bound:tt $(+ $others:tt)*) => {{
        let ptr = GlobalBox::into_raw($boxed);
        unsafe { GlobalBox::from_raw(ptr as *mut (dyn $bound $(+ $others)*)) }
    }}
}

/// A [`TryBox`] wrapper which uses the global memory allocator.
#[derive(Debug)]
pub struct GlobalBox<T: ?Sized>(TryBox<T, &'static SvsmAllocator>);

impl<T> GlobalBox<T> {
    /// See the documentation for [`TryBox::try_new_in()`].
    #[inline]
    pub fn try_new(val: T) -> Result<Self, SvsmError> {
        let inner = TryBox::try_new_in(val, &ALLOCATOR)?;
        Ok(Self(inner))
    }

    /// See the documentation for [`TryBox::try_new_uninit_in()`].
    #[inline]
    pub fn try_new_uninit() -> Result<GlobalBox<MaybeUninit<T>>, SvsmError> {
        let inner = TryBox::try_new_uninit_in(&ALLOCATOR)?;
        Ok(GlobalBox(inner))
    }

    /// See the documentation for [`TryBox::try_new_zeroed_in()`].
    #[inline]
    pub fn try_new_zeroed() -> Result<GlobalBox<MaybeUninit<T>>, SvsmError> {
        let inner = TryBox::try_new_zeroed_in(&ALLOCATOR)?;
        Ok(GlobalBox(inner))
    }

    /// See the documentation for [`TryBox::into_inner()`].
    #[inline]
    pub fn into_inner(self) -> T {
        TryBox::into_inner(self.0)
    }
}

impl<T: ?Sized> GlobalBox<T> {
    /// # Safety
    ///
    /// See the safety requirements for [`TryBox::from_raw_in()`].
    #[inline]
    pub unsafe fn from_raw(raw: *mut T) -> Self {
        Self(TryBox::from_raw_in(raw, &ALLOCATOR))
    }

    #[inline]
    /// See the documentation for [`TryBox::into_raw`].
    pub fn into_raw(b: Self) -> *mut T {
        TryBox::into_raw(b.0)
    }
}

impl<T> GlobalBox<MaybeUninit<T>> {
    /// # Safety
    ///
    /// See safety requirements for [`TryBox::assume_init()`].
    #[inline]
    pub unsafe fn assume_init(self) -> GlobalBox<T> {
        GlobalBox(TryBox::assume_init(self.0))
    }
}

impl<T: ?Sized + Default> GlobalBox<T> {
    /// Allocates memory in the given allocator and places the default value
    /// for `T` into it.
    #[inline]
    pub fn try_default() -> Result<Self, TryAllocError> {
        TryBox::try_default_in(&ALLOCATOR).map(Self)
    }
}

impl<T: ?Sized> From<TryBox<T, &'static SvsmAllocator>> for GlobalBox<T> {
    fn from(boxed: TryBox<T, &'static SvsmAllocator>) -> Self {
        Self(boxed)
    }
}

impl<T: ?Sized> From<GlobalBox<T>> for TryBox<T, &'static SvsmAllocator> {
    fn from(boxed: GlobalBox<T>) -> Self {
        boxed.0
    }
}

impl<T: ?Sized> AsRef<TryBox<T, &'static SvsmAllocator>> for GlobalBox<T> {
    fn as_ref(&self) -> &TryBox<T, &'static SvsmAllocator> {
        &self.0
    }
}

impl<T: ?Sized> AsMut<TryBox<T, &'static SvsmAllocator>> for GlobalBox<T> {
    fn as_mut(&mut self) -> &mut TryBox<T, &'static SvsmAllocator> {
        &mut self.0
    }
}

impl<T: ?Sized> AsRef<T> for GlobalBox<T> {
    fn as_ref(&self) -> &T {
        TryBox::as_ref(&self.0)
    }
}

impl<T: ?Sized> AsMut<T> for GlobalBox<T> {
    fn as_mut(&mut self) -> &mut T {
        TryBox::as_mut(&mut self.0)
    }
}

impl<T: ?Sized> Deref for GlobalBox<T> {
    type Target = T;

    fn deref(&self) -> &T {
        TryBox::deref(self.as_ref())
    }
}

impl<T: ?Sized> DerefMut for GlobalBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        TryBox::deref_mut(self.as_mut())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(test_in_svsm))]
    extern crate std;
    #[cfg(test_in_svsm)]
    use super::ALLOCATOR as Alloc;
    use super::*;
    #[cfg(not(test_in_svsm))]
    use std::alloc::System as Alloc;

    #[test]
    fn box_try_new() {
        let obj = TryBox::try_new_in(5, &Alloc).unwrap();
        assert_eq!(*obj, 5);
    }

    #[test]
    fn box_try_uninit() {
        let mut obj = TryBox::<u32, _>::try_new_uninit_in(&Alloc).unwrap();
        // SAFETY: TryBox owns valid memory. Memory is initialized before use.
        let init = unsafe {
            obj.as_mut_ptr().write(5);
            obj.assume_init()
        };
        assert_eq!(*init, 5);
    }

    #[test]
    fn box_try_uninit_write() {
        let obj = TryBox::<u32, _>::try_new_uninit_in(&Alloc).unwrap();
        let init = TryBox::write(obj, 7);
        assert_eq!(*init, 7);
    }

    #[test]
    fn box_try_zeroed() {
        let obj = TryBox::<u32, _>::try_new_zeroed_in(&Alloc).unwrap();
        // SAFETY: memory is initialized to zero, which is valid for u32
        let init = unsafe { obj.assume_init() };
        assert_eq!(*init, 0);
    }

    #[test]
    fn box_nested_deref() {
        let inner = TryBox::try_new_in([13; 32], &Alloc).unwrap();
        {
            let outer = TryBox::try_new_in(inner, &Alloc).unwrap();
            assert_eq!(**outer, [13; 32]);
        }
    }

    #[test]
    fn box_try_clone() {
        let first = TryBox::try_new_in([13; 32], &Alloc).unwrap();
        let second = first.try_clone().unwrap();
        drop(first);
        assert_eq!(*second, [13; 32]);
    }

    #[test]
    fn box_try_clone_mut() {
        let mut first = TryBox::try_new_in([13; 32], &Alloc).unwrap();
        let second = first.try_clone().unwrap();
        first.fill(14);
        assert_eq!(*second, [13; 32]);
        assert_eq!(*first, [14; 32]);
    }
}
