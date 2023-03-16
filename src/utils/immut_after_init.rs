// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>

use core::cell::UnsafeCell;
use core::marker::Copy;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::Deref;

/// A memory location which is effectively immutable after initalization code
/// has run.
///
/// The use of global variables initialized once from code requires either
/// making them `static mut`, which is (on the way of getting) deprecated
/// (c.f. [Consider deprecation of UB-happy `static
/// mut`](https://github.com/rust-lang/rust/issues/53639)), or wrapping them in
/// one of the [`core::cell`] types. However, those either would require to mark
/// each access as `unsafe{}`, including loads from the value, or incur some
/// runtime and storage overhead.
///
/// Using `ImmutAfterInitCell` as an alternative makes the intended usage
/// pattern more verbatim and limits the `unsafe{}` regions to the
/// initialization code.  The main purpose is to facilitate code review: it must
/// get verified that the value gets initialized only once and before first
/// potential use.
///
/// # Examples
/// A `ImmutAfterInitCell` may start out in unitialized state and can get
/// initialized at runtime:
/// ```
/// # use svsm::utils::immut_after_init::ImmutAfterInitCell;
/// static X : ImmutAfterInitCell<i32> = ImmutAfterInitCell::uninit();
/// pub fn main() {
///     unsafe { X.init(&123) };
///     assert_eq!(*X, 123);
/// }
/// ```
///
/// Also, to support early/late initialization scenarios, a
/// `ImmutAfterInitCell`'s value may get reset after having been initialized
/// already:
/// ```
/// # use svsm::utils::immut_after_init::ImmutAfterInitCell;
/// static X : ImmutAfterInitCell<i32> = ImmutAfterInitCell::new(0);
/// pub fn main() {
///     assert_eq!(*X, 0);
///     unsafe { X.reinit(&123) };
///     assert_eq!(*X, 123);
/// }
/// ```
///
#[repr(transparent)]
pub struct ImmutAfterInitCell<T> {
    #[doc(hidden)]
    data: UnsafeCell<MaybeUninit<T>>,
}

impl<T> ImmutAfterInitCell<T> {
    /// Create an unitialized `ImmutAfterInitCell` instance. The value must get
    /// initialized by means of [`Self::init()`] before first usage.
    pub const fn uninit() -> Self {
        ImmutAfterInitCell {
            data: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Create an initialized `ImmutAfterInitCell` instance from a value.
    ///
    /// * `v` - Initialization value.
    pub const fn new(v: T) -> Self {
        ImmutAfterInitCell {
            data: UnsafeCell::new(MaybeUninit::new(v)),
        }
    }
}

impl<T> ImmutAfterInitCell<T> {
    /// Initialize an uninitialized `ImmutAfterInitCell` instance from a value.
    ///
    /// Must **not** get called on an already initialized instance!
    ///
    /// * `v` - Initialization value.
    pub unsafe fn init(&self, v: T) {
        (*self.data.get()).as_mut_ptr().write(v);
    }

    /// Reinitialize an initialized `ImmutAfterInitCell` instance from a value.
    ///
    /// Must **not** get called while any borrow via [`Self::deref()`] or
    /// [`ImmutAfterInitRef::deref()`]is alive!
    ///
    /// * `v` - Initialization value.
    pub unsafe fn reinit(&self, v: T) {
        self.init(v);
    }
}

impl<T: Copy> ImmutAfterInitCell<T> {
    /// Initialize an uninitialized `ImmutAfterInitCell` instance with a copy.
    ///
    /// Must **not** get called on an already initialized instance!
    ///
    /// * `v` - Initialization value.
    pub unsafe fn init_copy_from(&self, v: &T) {
        core::ptr::copy_nonoverlapping(v as *const T, (*self.data.get()).as_mut_ptr(), 1);
    }
}

impl<T> Deref for ImmutAfterInitCell<T> {
    type Target = T;

    /// Dereference the wrapped value. Must **only ever** get called on an
    /// initialized instance!
    fn deref(&self) -> &T {
        unsafe { (&*self.data.get()).assume_init_ref() }
    }
}

unsafe impl<T> Send for ImmutAfterInitCell<T> {}
unsafe impl<T> Sync for ImmutAfterInitCell<T> {}

/// A reference to a memory location which is effectively immutable after
/// initalization code has run.
///

/// A `ImmutAfterInitRef` can either get initialized statically at link time or
/// once from initialization code, basically following the protocol of a
/// [`ImmutAfterInitCell`] itself:
///
/// # Examples
/// A `ImmutAfterInitRef` can be initialized to either point to a
/// `ImmutAfterInitCell`'s contents,
/// ```
/// # use svsm::utils::immut_after_init::{ImmutAfterInitCell, ImmutAfterInitRef};
/// static X : ImmutAfterInitCell<i32> = ImmutAfterInitCell::uninit();
/// static RX : ImmutAfterInitRef<'_, i32> = ImmutAfterInitRef::uninit();
/// fn main() {
///     unsafe { X.init(&123) };
///     unsafe { RX.init_from_cell(&X) };
///     assert_eq!(*RX, 123);
/// }
/// ```
/// or to plain value directly:
/// ```
/// # use svsm::utils::immut_after_init::ImmutAfterInitRef;
/// static X : i32 = 123;
/// static RX : ImmutAfterInitRef<'_, i32> = ImmutAfterInitRef::uninit();
/// fn main() {
///     unsafe { RX.init_from_ref(&X) };
///     assert_eq!(*RX, 123);
/// }
/// ```
///
/// Also, a `ImmutAfterInitRef` can get initialized by dereferencing another,
/// possibly temporary `ImmutAfterInitRef`, with the temporary again either
/// dereferencing a [`ImmutAfterInitCell`]'s contents,
/// ```
/// # use svsm::utils::immut_after_init::{ImmutAfterInitCell, ImmutAfterInitRef};
/// static RX : ImmutAfterInitRef::<'static, i32> = ImmutAfterInitRef::uninit();
///
/// fn init_rx(r : ImmutAfterInitRef<'static, i32>) {
///     unsafe { RX.init_from_ref(r.get()) };
/// }
///
/// static X : ImmutAfterInitCell<i32> = ImmutAfterInitCell::uninit();
///
/// fn main() {
///     unsafe { X.init(&123) };
///
///     init_rx(ImmutAfterInitRef::new_from_cell(&X));
///     assert_eq!(*RX, 123);
/// }
/// ```
/// or a plain value directly:
/// ```
/// # use svsm::utils::immut_after_init::ImmutAfterInitRef;
/// static RX : ImmutAfterInitRef::<'static, i32> = ImmutAfterInitRef::uninit();
//
/// fn init_rx(r : ImmutAfterInitRef<'static, i32>) {
///     unsafe { RX.init_from_ref(r.get()) };
/// }
///
/// static X : i32 = 123;
///
/// fn main() {
///     init_rx(ImmutAfterInitRef::new_from_ref(&X));
///     assert_eq!(*RX, 123);
/// }
/// ```
///
#[repr(transparent)]
pub struct ImmutAfterInitRef<'a, T: 'a> {
    #[doc(hidden)]
    ptr: ImmutAfterInitCell<*const T>,
    #[doc(hidden)]
    _phantom: PhantomData<&'a mut &'a T>,
}

impl<'a, T> ImmutAfterInitRef<'a, T> {
    /// Create an unitialized `ImmutAfterInitRef` instance. The reference itself
    /// must get initialized via either of [`Self::init_from_ref()`] or
    /// [`Self::init_from_cell()`] before first dereferencing it.
    pub const fn uninit() -> Self {
        ImmutAfterInitRef {
            ptr: ImmutAfterInitCell::uninit(),
            _phantom: PhantomData,
        }
    }

    /// Initialize an uninitialized `ImmutAfterInitRef` instance to point to value
    /// specified by a regular reference.
    ///
    /// Must **not** get called on an already initialized `ImmutAfterInitRef`
    /// instance!
    ///
    /// * `r` - Reference to the value to make the `ImmutAfterInitRef` to refer
    ///         to. By convention, the referenced value must have been
    ///         initialized already.
    pub unsafe fn init_from_ref<'b>(&self, r: &'b T)
    where
        'b: 'a,
    {
        self.ptr.init(r as *const T);
    }

    /// Create an initialized `ImmutAfterInitRef` instance pointing to a value
    /// specified by a regular reference.
    ///
    /// * `r` - Reference to the value to make the `ImmutAfterInitRef` to refer
    ///         to. By convention, the referenced value must have been
    ///         initialized already.
    pub const fn new_from_ref(r: &'a T) -> Self {
        Self {
            ptr: ImmutAfterInitCell::new(r as *const T),
            _phantom: PhantomData,
        }
    }

    /// Dereference the referenced value with lifetime propagation. Must **only
    /// ever** get called on an initialized `ImmutAfterInitRef` instance! Moreover,
    /// the value referenced must have been initialized as well.
    pub fn get(&self) -> &'a T {
        unsafe { &**self.ptr }
    }
}

impl<'a, T> ImmutAfterInitRef<'a, T> {
    /// Initialize an uninitialized `ImmutAfterInitRef` instance to point to
    /// value wrapped in a [`ImmutAfterInitCell`].
    ///
    /// Must **not** get called on an already initialized `ImmutAfterInitRef` instance!
    ///
    /// * `cell` - The value to make the `ImmutAfterInitRef` to refer to. By
    ///            convention, the referenced value must have been initialized
    ///            already.
    pub unsafe fn init_from_cell<'b>(&self, cell: &'b ImmutAfterInitCell<T>)
    where
        'b: 'a,
    {
        self.ptr.init((*cell.data.get()).as_ptr());
    }

    /// Create an initialized `ImmutAfterInitRef` instance pointing to a value
    /// wrapped in a [`ImmutAfterInitCell`].
    ///
    /// * `cell` - The value to make the `ImmutAfterInitRef` to refer to. By
    ///            convention, the referenced value must have been initialized
    ///            already.
    pub const fn new_from_cell(cell: &'a ImmutAfterInitCell<T>) -> Self {
        Self {
            ptr: ImmutAfterInitCell::new(unsafe { &*cell.data.get() }.as_ptr()),
            _phantom: PhantomData,
        }
    }
}

impl<'a, T> Deref for ImmutAfterInitRef<'a, T> {
    type Target = T;

    /// Dereference the referenced value *without* lifetime propagation. Must
    /// **only ever** get called on an initialized `ImmutAfterInitRef` instance!
    /// Moreover, the value referenced must have been initialized as well. If
    /// lifetime propagation is needed, use [`ImmutAfterInitRef::get()`].
    fn deref(&self) -> &T {
        self.get()
    }
}

unsafe impl<'a, T> Send for ImmutAfterInitRef<'a, T> {}
unsafe impl<'a, T> Sync for ImmutAfterInitRef<'a, T> {}
