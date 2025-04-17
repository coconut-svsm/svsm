// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::sync::atomic::{AtomicU8, Ordering};

pub type ImmutAfterInitResult<T> = Result<T, ImmutAfterInitError>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ImmutAfterInitError {
    AlreadyInit,
    Uninitialized,
}

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
/// static X: ImmutAfterInitCell<i32> = ImmutAfterInitCell::uninit();
/// pub fn main() {
///     unsafe { X.init_from_ref(&123) };
///     assert_eq!(*X, 123);
/// }
/// ```
#[derive(Debug)]
pub struct ImmutAfterInitCell<T> {
    #[doc(hidden)]
    data: UnsafeCell<MaybeUninit<T>>,
    #[doc(hidden)]
    init: AtomicU8,
}

const IMMUT_UNINIT: u8 = 0;
const IMMUT_INIT_IN_PROGRESS: u8 = 1;
const IMMUT_INITIALIZED: u8 = 2;

impl<T> ImmutAfterInitCell<T> {
    /// Create an unitialized `ImmutAfterInitCell` instance. The value must get
    /// initialized by means of [`Self::init()`] before first usage.
    pub const fn uninit() -> Self {
        Self {
            data: UnsafeCell::new(MaybeUninit::uninit()),
            init: AtomicU8::new(IMMUT_UNINIT),
        }
    }

    fn check_init(&self) -> ImmutAfterInitResult<()> {
        if self.init.load(Ordering::Acquire) == IMMUT_INITIALIZED {
            Ok(())
        } else {
            Err(ImmutAfterInitError::Uninitialized)
        }
    }

    fn try_init(&self) -> ImmutAfterInitResult<()> {
        self.init
            .compare_exchange(
                IMMUT_UNINIT,
                IMMUT_INIT_IN_PROGRESS,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .map_err(|_| ImmutAfterInitError::AlreadyInit)?;
        Ok(())
    }

    /// # Safety
    /// The caller must ensure that the cell is in the init-in-progress phase
    /// and that the contents of the cell have been populated.
    unsafe fn complete_init(&self) {
        self.init.store(IMMUT_INITIALIZED, Ordering::Release);
    }

    /// Obtains the inner value of the cell, returning `Ok(T)` if the cell is
    /// initialized or `Err(ImmutAfterInitError)` if not.
    pub fn try_get_inner(&self) -> ImmutAfterInitResult<&T> {
        self.check_init()?;
        let r = unsafe { (*self.data.get()).assume_init_ref() };
        Ok(r)
    }

    /// Initialize an uninitialized `ImmutAfterInitCell` instance from a value.
    /// Will fail if called on an initialized instance.
    ///
    /// * `v` - Initialization value.
    pub fn init(&self, v: T) -> ImmutAfterInitResult<()> {
        self.try_init()?;
        // SAFETY: Successful completion of `try_init` conveys the exclusive
        // right to populate the contents of the cell.
        unsafe {
            let data = &mut *self.data.get();
            data.write(v);
            self.complete_init();
        }
        Ok(())
    }

    /// Initialize an uninitialized `ImmutAfterInitCell` instance from a
    /// reference.
    /// Will fail if called on an initialized instance.
    ///
    /// * `v` - Initialization reference.
    pub fn init_from_ref(&self, r: &T) -> ImmutAfterInitResult<()>
    where
        T: Copy,
    {
        self.try_init()?;
        // SAFETY: Successful completion of `try_init` conveys the exclusive
        // right to populate the contents of the cell.
        unsafe {
            (*self.data.get())
                .as_mut_ptr()
                .copy_from_nonoverlapping(r, 1);
            self.complete_init();
        }
        Ok(())
    }
}

impl<T> Deref for ImmutAfterInitCell<T> {
    type Target = T;

    /// Dereference the wrapped value.  Will panic if called on an
    /// uninitialized instance.
    fn deref(&self) -> &T {
        self.try_get_inner().unwrap()
    }
}

impl<T> Drop for ImmutAfterInitCell<T> {
    fn drop(&mut self) {
        // Dropping is only required if the cell has been initialized.
        if self.init.load(Ordering::Relaxed) == IMMUT_INITIALIZED {
            // SAFETY: the initialization check ensures that the cell holds
            // initialized data.
            unsafe {
                let cell = &mut *self.data.get();
                // This drop will never occur for a cell that was initialized
                // from a reference, because initialization from a reference
                // requires `Copy` and types that implement `Copy` do not
                // implement `Drop`, and thus this will have no effect for such
                // types.
                cell.assume_init_drop();
            }
        }
    }
}

unsafe impl<T: Send> Send for ImmutAfterInitCell<T> {}
unsafe impl<T: Send + Sync> Sync for ImmutAfterInitCell<T> {}

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
/// static X: ImmutAfterInitCell<i32> = ImmutAfterInitCell::uninit();
/// static RX: ImmutAfterInitRef<'_, i32> = ImmutAfterInitRef::uninit();
/// fn main() {
///     unsafe { X.init_from_ref(&123) };
///     unsafe { RX.init_from_cell(&X) };
///     assert_eq!(*RX, 123);
/// }
/// ```
/// or to plain value directly:
/// ```
/// # use svsm::utils::immut_after_init::ImmutAfterInitRef;
/// static X: i32 = 123;
/// static RX: ImmutAfterInitRef<'_, i32> = ImmutAfterInitRef::uninit();
/// fn main() {
///     unsafe { RX.init_from_ref(&X) };
///     assert_eq!(*RX, 123);
/// }
/// ```
///
/// Also, an `ImmutAfterInitRef` can be initialized by obtaining a reference
/// from another `ImmutAfterInitRef`:
/// ```
/// # use svsm::utils::immut_after_init::ImmutAfterInitRef;
/// static RX: ImmutAfterInitRef<'static, i32> = ImmutAfterInitRef::uninit();
///
/// fn init_rx(r: ImmutAfterInitRef<'static, i32>) {
///     unsafe { RX.init_from_ref(r.get()) };
/// }
///
/// static X: i32 = 123;
///
/// fn main() {
///     let local = ImmutAfterInitRef::<i32>::uninit();
///     local.init_from_ref(&X);
///     init_rx(local);
///     assert_eq!(*RX, 123);
/// }
/// ```
#[derive(Debug)]
pub struct ImmutAfterInitRef<'a, T: Copy> {
    #[doc(hidden)]
    ptr: ImmutAfterInitCell<*const T>,
    #[doc(hidden)]
    _phantom: PhantomData<&'a &'a T>,
}

impl<'a, T: Copy> ImmutAfterInitRef<'a, T> {
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
    /// specified by a regular reference.  Will fail if called on an
    /// initialized instance.
    ///
    /// * `r` - Reference to the value to make the `ImmutAfterInitRef` to refer
    ///         to. By convention, the referenced value must have been
    ///         initialized already.
    pub fn init_from_ref<'b>(&self, r: &'b T) -> ImmutAfterInitResult<()>
    where
        'b: 'a,
    {
        self.ptr.init(r as *const T)
    }

    /// Dereference the referenced value with lifetime propagation.  Will panic
    /// if called on an uninitialized instance.
    pub fn get(&self) -> &'a T {
        unsafe { &**self.ptr }
    }

    /// Initialize an uninitialized `ImmutAfterInitRef` instance to point to
    /// value wrapped in a [`ImmutAfterInitCell`].
    ///
    /// Must **not** get called on an already initialized `ImmutAfterInitRef` instance!
    ///
    /// * `cell` - The value to make the `ImmutAfterInitRef` to refer to. By
    ///            convention, the referenced value must have been initialized
    ///            already.
    pub fn init_from_cell<'b>(&self, cell: &'b ImmutAfterInitCell<T>) -> ImmutAfterInitResult<()>
    where
        'b: 'a,
    {
        self.ptr.init(cell.try_get_inner()? as *const T)
    }
}

impl<T: Copy> Deref for ImmutAfterInitRef<'_, T> {
    type Target = T;

    /// Dereference the referenced value *without* lifetime propagation. Must
    /// **only ever** get called on an initialized `ImmutAfterInitRef` instance!
    /// Moreover, the value referenced must have been initialized as well. If
    /// lifetime propagation is needed, use [`ImmutAfterInitRef::get()`].
    fn deref(&self) -> &T {
        self.get()
    }
}

unsafe impl<T: Copy + Send> Send for ImmutAfterInitRef<'_, T> {}
unsafe impl<T: Copy + Send + Sync> Sync for ImmutAfterInitRef<'_, T> {}

#[cfg(test)]
mod tests {

    use crate::utils::immut_after_init::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn test_with_move() {
        let v = AtomicU32::new(5);
        let immut = ImmutAfterInitCell::<AtomicU32>::uninit();
        match immut.try_get_inner() {
            Ok(_) => panic!("uninitialized cell returned Ok()"),
            Err(e) => assert_eq!(e, ImmutAfterInitError::Uninitialized),
        }
        let init = immut.init(v);
        if init.is_err() {
            panic!("initializing uninitialized cell returned {:?}", init);
        }
        match immut.init(AtomicU32::new(0)) {
            Ok(_) => panic!("reinitializing initialized cell returned Ok()"),
            Err(e) => assert_eq!(e, ImmutAfterInitError::AlreadyInit),
        }

        assert_eq!(immut.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn test_with_copy() {
        let v: u32 = 5;
        let immut = ImmutAfterInitCell::<u32>::uninit();
        immut.init_from_ref(&v).expect("init failed");
        assert_eq!(*immut, 5);
    }

    struct ItemWithDrop<'a> {
        pub drop_count: &'a mut u32,
    }

    impl Drop for ItemWithDrop<'_> {
        fn drop(&mut self) {
            *self.drop_count += 1;
        }
    }

    #[test]
    fn test_with_drop() {
        let mut local_drop_count: u32 = 0;
        let item = ItemWithDrop {
            drop_count: &mut local_drop_count,
        };
        let immut = ImmutAfterInitCell::<ItemWithDrop<'_>>::uninit();
        immut.init(item).expect("init failed");
        drop(immut);
        assert_eq!(local_drop_count, 1);
    }
}
