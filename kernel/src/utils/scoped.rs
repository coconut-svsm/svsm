// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use core::ops::{Deref, DerefMut};

/// `ScopedRef` and `ScopedMut` are designed to solve the problem of managing
/// lifetimes of references created from pointers.  Normally, when a reference
/// is created from a pointer (such as with `ptr::as_ref()`), it is associated
/// with the static lifetime, and as a result, the compiler is unable to
/// determine whether the reference will live long enough for its intended
/// use.  While functions like `ptr::as_ref()` can associate the reference with
/// a lifetime, the compiler cannot usefully use this information to enforce
/// lifetime checks on pointers generated in this way because although every
/// reference can be bound to a lifetime, a reference does not by itself own a
/// lifetime, and without an owning lifetime, the compiler has no way to know
/// when the lifetime to which the reference is bound goes out of scope.
/// The `ScopedRef` and `ScopedMut` objects solve this by creating a new object
/// every time a pointer is converted to a reference, so there is an actual
/// object with an associated lifetime that the compiler can use to ensure that
/// the reference remains valid.

#[derive(Debug)]
pub struct ScopedRef<'a, T> {
    inner: &'a T,
}

impl<T> ScopedRef<'_, T> {
    /// Generates a new `ScopedRef` from a pointer.
    ///
    /// # Safety
    ///
    /// This is a dereference of a raw pointer, and no correctness checks are
    /// performed.
    pub unsafe fn new(ptr: *const T) -> Option<Self> {
        // SAFETY: the caller guarantees the safety of the pointer.
        unsafe { ptr.as_ref().map(|inner| Self { inner }) }
    }
}

impl<T> AsRef<T> for ScopedRef<'_, T> {
    fn as_ref(&self) -> &T {
        self.inner
    }
}

impl<T> Deref for ScopedRef<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.as_ref()
    }
}

impl<T> Drop for ScopedRef<'_, T> {
    fn drop(&mut self) {}
}

#[derive(Debug)]
pub struct ScopedMut<'a, T> {
    inner: &'a mut T,
}

impl<T> ScopedMut<'_, T> {
    /// Generates a new `ScopedMut` from a pointer.
    ///
    /// # Safety
    ///
    /// This is a dereference of a raw pointer, and no correctness checks are
    /// performed.
    pub unsafe fn new(ptr: *mut T) -> Option<Self> {
        // SAFETY: the caller guarantees the safety of the pointer.
        unsafe { ptr.as_mut().map(|inner| Self { inner }) }
    }
}

impl<T> AsRef<T> for ScopedMut<'_, T> {
    fn as_ref(&self) -> &T {
        self.inner
    }
}

impl<T> AsMut<T> for ScopedMut<'_, T> {
    fn as_mut(&mut self) -> &mut T {
        self.inner
    }
}

impl<T> Deref for ScopedMut<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.as_ref()
    }
}

impl<T> DerefMut for ScopedMut<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.as_mut()
    }
}

impl<T> Drop for ScopedMut<'_, T> {
    fn drop(&mut self) {}
}
