// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Red Hat
//
// Author: Oliver Steffen <osteffen@redhat.com>

use core::fmt;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};

use crate::locking::SpinLock;

/// A fixed-size object pool with internal locking.
///
/// Objects are checked out via [`Pool::get`] and automatically returned when
/// the [`PoolGuard`] is dropped. If the pool is empty on checkout, a
/// caller-provided factory creates a new object. If the pool is full on
/// return, the object is dropped.
pub struct Pool<T: Send, const N: usize> {
    objects: SpinLock<[Option<T>; N]>,
}

impl<T: Send, const N: usize> Pool<T, N> {
    /// Creates an empty pool suitable for use in `static` declarations.
    pub const fn empty() -> Self {
        Self {
            objects: SpinLock::new([const { None }; N]),
        }
    }

    /// Checks out an object from the pool, or creates one via `factory` if
    /// the pool is empty. The factory runs outside the lock.
    pub fn get<E>(&self, factory: impl FnOnce() -> Result<T, E>) -> Result<PoolGuard<'_, T, N>, E> {
        {
            let mut pool = self.objects.lock();
            for slot in pool.iter_mut() {
                if let Some(obj) = slot.take() {
                    return Ok(PoolGuard {
                        pool: self,
                        data: ManuallyDrop::new(obj),
                    });
                }
            }
        }
        let obj = factory()?;
        Ok(PoolGuard {
            pool: self,
            data: ManuallyDrop::new(obj),
        })
    }

    fn put(&self, obj: T) {
        let mut pool = self.objects.lock();
        for slot in pool.iter_mut() {
            if slot.is_none() {
                *slot = Some(obj);
                return;
            }
        }
    }
}

impl<T: Send, const N: usize> fmt::Debug for Pool<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool").field("capacity", &N).finish()
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
    }

    #[test]
    fn deref_mut_allows_modification() {
        let pool: Pool<u32, 2> = Pool::empty();
        let mut guard = pool.get(|| Ok::<_, ()>(10)).unwrap();
        *guard = 20;
        assert_eq!(*guard, 20);
    }

    #[test]
    fn overflow_drops_excess_objects() {
        let pool: Pool<u32, 1> = Pool::empty();
        {
            let _g1 = pool.get(|| Ok::<_, ()>(1)).unwrap();
            let _g2 = pool.get(|| Ok::<_, ()>(2)).unwrap();
        }
        let g = pool.get(|| Ok::<_, ()>(99)).unwrap();
        assert!(*g == 1 || *g == 2);
    }
}
