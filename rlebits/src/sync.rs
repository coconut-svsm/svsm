/// More scalable alternatives to global spin mutex for RleBits
///
/// This demonstrates several approaches for better scalability
use crate::{RleBits, RleBitsError};
use spin::{Mutex, RwLock};

/// Original thread-safe wrapper using a simple mutex
///
/// This is the simplest approach but can become a bottleneck under high contention.
/// All operations (reads and writes) serialize through a single mutex.
///
/// **Performance characteristics:**
/// - Read scalability: Poor (all reads serialize)
/// - Write scalability: Poor (all writes serialize)  
/// - Complexity: Simple
/// - Best for: Low contention scenarios
#[cfg(feature = "thread-safe")]
#[derive(Debug)]
pub struct ThreadSafeRleBits {
    inner: Mutex<RleBits>,
}

#[cfg(feature = "thread-safe")]
impl ThreadSafeRleBits {
    pub fn new(limit: usize, size: usize) -> Self {
        Self {
            inner: Mutex::new(RleBits::new(limit, size)),
        }
    }

    pub fn reset(&self) {
        let mut guard = self.inner.lock();
        guard.reset();
    }

    pub fn get(&self, index: usize) -> Option<bool> {
        let guard = self.inner.lock();
        guard.get(index)
    }

    pub fn get_run(&self, n: usize) -> usize {
        let guard = self.inner.lock();
        guard.get_run_length(n)
    }

    pub fn set(&self, index: usize, value: bool) -> Result<(), RleBitsError> {
        let mut guard = self.inner.lock();
        guard.set(index, value)
    }

    pub fn set_range(&self, index: usize, len: usize, value: bool) -> Result<(), RleBitsError> {
        let mut guard = self.inner.lock();
        guard.set_range(index, len, value)
    }

    pub fn sanity_check(&self) -> usize {
        let guard = self.inner.lock();
        guard.sanity_check()
    }

    #[cfg(any(feature = "std", test))]
    pub fn dump_with<F>(&self, format_addr: F)
    where
        F: Fn(usize) -> std::string::String,
    {
        let guard = self.inner.lock();
        guard.dump_with(format_addr);
    }

    /// For advanced use cases where you need to perform multiple operations atomically
    pub fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut RleBits) -> R,
    {
        let mut guard = self.inner.lock();
        f(&mut guard)
    }
}

// ThreadSafeRleBits is Send and Sync because spin::Mutex is Send and Sync
#[cfg(feature = "thread-safe")]
unsafe impl Send for ThreadSafeRleBits {}
#[cfg(feature = "thread-safe")]
unsafe impl Sync for ThreadSafeRleBits {}

/// Read-Write Lock approach
/// Allows multiple concurrent readers, exclusive writers
#[cfg(feature = "thread-safe")]
#[derive(Debug)]
pub struct RwLockRleBits {
    inner: RwLock<RleBits>,
}

#[cfg(feature = "thread-safe")]
impl RwLockRleBits {
    pub fn new(limit: usize, size: usize) -> Self {
        Self {
            inner: RwLock::new(RleBits::new(limit, size)),
        }
    }

    pub fn reset(&self) {
        let mut guard = self.inner.write();
        guard.reset();
    }

    /// Multiple threads can read concurrently
    pub fn get(&self, index: usize) -> Option<bool> {
        let guard = self.inner.read();
        guard.get(index)
    }

    pub fn get_run(&self, n: usize) -> usize {
        let guard = self.inner.read();
        guard.get_run_length(n)
    }

    /// Writers get exclusive access
    pub fn set(&self, index: usize, value: bool) -> Result<(), RleBitsError> {
        let mut guard = self.inner.write();
        guard.set(index, value)
    }

    pub fn set_range(&self, index: usize, len: usize, value: bool) -> Result<(), RleBitsError> {
        let mut guard = self.inner.write();
        guard.set_range(index, len, value)
    }

    pub fn sanity_check(&self) -> usize {
        let guard = self.inner.read();
        guard.sanity_check()
    }

    #[cfg(any(feature = "std", test))]
    pub fn dump_with<F>(&self, format_addr: F)
    where
        F: Fn(usize) -> std::string::String,
    {
        let guard = self.inner.read();
        guard.dump_with(format_addr);
    }
}
