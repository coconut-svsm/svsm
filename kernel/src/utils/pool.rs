// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Red Hat
//
// Author: Oliver Steffen <osteffen@redhat.com>

use core::fmt;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};

use crate::locking::SpinLock;

/// Inner state of a [`Pool`], protected by the pool's lock.
///
/// Pooled objects are kept in a stack: `objects[..count]` holds the stacked
/// objects and `objects[count..]` is `None`.
///
/// # Invariants
///
/// - `count <= N`
/// - `objects[..count]` are all `Some`
/// - `objects[count..]` are all `None`
///
/// `count` is the single source of truth for the occupancy of the pool; the
/// array must always agree with it.
struct PoolInner<T, const N: usize> {
    objects: [Option<T>; N],
    count: usize,
}

impl<T, const N: usize> PoolInner<T, N> {
    const fn new() -> Self {
        Self {
            objects: [const { None }; N],
            count: 0,
        }
    }

    /// Pushes `obj` onto the stack.
    ///
    /// Returns `obj` back to the caller if the pool already holds `N`
    /// objects, so that the caller can dispose of it outside of the lock.
    fn push(&mut self, obj: T) -> Option<T> {
        if self.count == N {
            return Some(obj);
        }

        self.objects[self.count] = Some(obj);
        self.count += 1;

        None
    }

    /// Pops the most recently pushed object off the stack.
    fn pop(&mut self) -> Option<T> {
        if self.count == 0 {
            return None;
        }

        self.count -= 1;
        let obj = self.objects[self.count].take();

        debug_assert!(obj.is_some(), "pool invariant violated");

        obj
    }
}

/// A fixed-size object pool with internal locking.
///
/// Objects are checked out via [`Pool::get`] and automatically returned when
/// the [`PoolGuard`] is dropped. If the pool is empty on checkout, a
/// caller-provided factory creates a new object. If the pool is full on
/// return, the object is dropped.
///
/// Objects are reused in last-in, first-out order, and they are *not* reset
/// or cleared before being handed out again: whatever state the previous
/// owner left behind is visible to the next one. Only pool types for which
/// that is acceptable, or which reset themselves when checked out, should be
/// used.
///
/// # Capacity
///
/// `N` bounds the number of objects *retained* for reuse; it is not a bound
/// on the number of objects in existence. The factory runs outside of the
/// lock, so any number of concurrent [`Pool::get`] calls can observe an empty
/// pool and create objects in parallel.
///
/// # Locking
///
/// The pool is guarded by a [`SpinLock`], which is not IRQ safe: it must not
/// be used from interrupt context.
pub struct Pool<T: Send, const N: usize> {
    inner: SpinLock<PoolInner<T, N>>,
}

impl<T: Send, const N: usize> Pool<T, N> {
    /// Creates an empty pool suitable for use in `static` declarations.
    pub const fn empty() -> Self {
        Self {
            inner: SpinLock::new(PoolInner::new()),
        }
    }

    /// Checks out an object from the pool, or creates one via `factory` if
    /// the pool is empty.
    ///
    /// The factory runs outside the lock, so it may allocate, block or even
    /// call back into this pool.
    pub fn get<E>(&self, factory: impl FnOnce() -> Result<T, E>) -> Result<PoolGuard<'_, T, N>, E> {
        // The lock must be released before `factory` is invoked below, since
        // the factory may allocate, block or call back into this pool. Binding
        // in a `let` statement gets that right: its temporaries -- including
        // the lock guard -- are dropped at the end of the statement.
        //
        // Do not inline the `lock()` into a `match` scrutinee instead:
        // temporaries there live until the end of the whole `match`
        // expression, and the pool would stay locked across the factory call.
        let pooled_obj = self.inner.lock().pop();

        let obj = match pooled_obj {
            Some(obj) => obj,
            None => factory()?,
        };

        Ok(PoolGuard {
            pool: self,
            data: ManuallyDrop::new(obj),
        })
    }

    /// Returns the number of objects currently held by the pool.
    pub fn len(&self) -> usize {
        self.inner.lock().count
    }

    /// Returns `true` if the pool currently holds no objects.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn put(&self, obj: T) {
        // The lock guard is a temporary of this statement, dropped at its end,
        // so the surplus object is disposed of outside of the lock: `T::drop()`
        // may be expensive, take locks of its own, or re-enter this pool.
        let surplus_obj = self.inner.lock().push(obj);
        drop(surplus_obj);
    }
}

impl<T: Send, const N: usize> fmt::Debug for Pool<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("capacity", &N)
            .field("len", &self.len())
            .finish()
    }
}

/// RAII guard that returns its object to the originating [`Pool`] on drop.
///
/// Dereferences to the contained `T`, allowing direct use of the pooled
/// object.
pub struct PoolGuard<'a, T: Send, const N: usize> {
    pool: &'a Pool<T, N>,
    data: ManuallyDrop<T>,
}

impl<T: Send, const N: usize> Deref for PoolGuard<'_, T, N> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.data.deref()
    }
}

impl<T: Send, const N: usize> DerefMut for PoolGuard<'_, T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data.deref_mut()
    }
}

impl<T: Send, const N: usize> Drop for PoolGuard<'_, T, N> {
    fn drop(&mut self) {
        // SAFETY: `self.data` cannot be used again, since this is
        // the drop() implementation.
        let obj = unsafe { ManuallyDrop::take(&mut self.data) };
        self.pool.put(obj);
    }
}

impl<T: Send, const N: usize> fmt::Debug for PoolGuard<'_, T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolGuard").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn get_from_empty_pool_calls_factory() {
        let pool: Pool<u32, 2> = Pool::empty();
        let guard = pool.get(|| Ok::<_, ()>(42)).unwrap();
        assert_eq!(*guard, 42);
    }

    #[test]
    fn object_returned_to_pool_on_drop() {
        let pool: Pool<u32, 2> = Pool::empty();
        {
            let guard = pool.get(|| Ok::<_, ()>(42)).unwrap();
            assert_eq!(*guard, 42);
        }
        let guard = pool.get(|| Ok::<_, ()>(99)).unwrap();
        assert_eq!(*guard, 42);
    }

    #[test]
    fn factory_error_propagated() {
        let pool: Pool<u32, 2> = Pool::empty();
        let result = pool.get(|| Err::<u32, &str>("failed"));
        assert!(result.is_err());
        // A failed `get()` must not leave anything behind in the pool.
        assert!(pool.is_empty());
    }

    #[test]
    fn deref_mut_allows_modification() {
        let pool: Pool<u32, 2> = Pool::empty();
        let mut guard = pool.get(|| Ok::<_, ()>(10)).unwrap();
        *guard = 20;
        assert_eq!(*guard, 20);
    }

    #[test]
    fn len_tracks_checkout_and_return() {
        let pool: Pool<u32, 2> = Pool::empty();
        assert!(pool.is_empty());

        let g1 = pool.get(|| Ok::<_, ()>(1)).unwrap();
        assert!(pool.is_empty());

        drop(g1);
        assert_eq!(pool.len(), 1);

        let g1 = pool.get(|| Ok::<_, ()>(1)).unwrap();
        let g2 = pool.get(|| Ok::<_, ()>(2)).unwrap();
        assert!(pool.is_empty());

        drop(g1);
        drop(g2);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn pool_is_lifo() {
        let pool: Pool<u32, 2> = Pool::empty();

        // Check out two objects and return them in a known order.
        let g1 = pool.get(|| Ok::<_, ()>(1)).unwrap();
        let g2 = pool.get(|| Ok::<_, ()>(2)).unwrap();
        drop(g1);
        drop(g2);

        // The most recently returned object comes back out first. Both slots
        // are checked out at the same time, so the factory must not be called.
        let g1 = pool
            .get(|| Err::<u32, &str>("factory must not be called"))
            .unwrap();
        let g2 = pool
            .get(|| Err::<u32, &str>("factory must not be called"))
            .unwrap();
        assert_eq!(*g1, 2);
        assert_eq!(*g2, 1);
    }

    #[test]
    fn zero_sized_pool_never_retains_objects() {
        let pool: Pool<u32, 0> = Pool::empty();
        {
            let _g = pool.get(|| Ok::<_, ()>(1)).unwrap();
        }
        assert!(pool.is_empty());
        // Nothing was retained, so the factory is called again.
        let g = pool.get(|| Ok::<_, ()>(2)).unwrap();
        assert_eq!(*g, 2);
    }

    #[test]
    fn factory_may_reenter_pool() {
        let pool: Pool<u32, 1> = Pool::empty();

        // The factory runs with the pool lock released. If a regression holds
        // the lock across the factory call, this test spins forever instead
        // of failing.
        let guard = pool
            .get(|| pool.get(|| Ok::<_, ()>(7)).map(|inner| *inner))
            .unwrap();
        assert_eq!(*guard, 7);
    }

    /// Object that counts its own drops and probes the pool from `drop()`.
    struct DropProbe;

    static DROP_PROBE_POOL: Pool<DropProbe, 1> = Pool::empty();
    static DROP_COUNT: AtomicUsize = AtomicUsize::new(0);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            DROP_COUNT.fetch_add(1, Ordering::Relaxed);
            // Takes the pool lock. If the surplus object were dropped while
            // the pool lock is held, this spins forever.
            let _ = DROP_PROBE_POOL.is_empty();
        }
    }

    #[test]
    fn surplus_object_dropped_outside_lock() {
        let g1 = DROP_PROBE_POOL.get(|| Ok::<_, ()>(DropProbe)).unwrap();
        // Pool size is 1, this creates an excess object
        let g2 = DROP_PROBE_POOL.get(|| Ok::<_, ()>(DropProbe)).unwrap();

        drop(g2);
        assert_eq!(DROP_COUNT.load(Ordering::Relaxed), 0);
        assert_eq!(DROP_PROBE_POOL.len(), 1);

        // The pool is full now, so g1 is not returned
        drop(g1);
        assert_eq!(DROP_COUNT.load(Ordering::Relaxed), 1);
        assert_eq!(DROP_PROBE_POOL.len(), 1);
    }

    #[test]
    fn overflow_drops_excess_objects() {
        let pool: Pool<u32, 1> = Pool::empty();
        {
            let _g1 = pool.get(|| Ok::<_, ()>(1)).unwrap();
            let _g2 = pool.get(|| Ok::<_, ()>(2)).unwrap();
            // `_g2` is dropped first and retained, `_g1` is dropped
        }

        let g = pool.get(|| Ok::<_, ()>(99)).unwrap();
        assert_eq!(*g, 2);
    }
}
