// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 SUSE LLC
//
// Author: Carlos López <clopez@suse.de>

//! Per-CPU tracking of held read-write locks to detect same-CPU reentrancy
//! deadlocks.
//!
//! Each CPU holds a list of the [`RWLock`](super::rwlock::RawRWLock)s it holds,
//! and each blocking acquisition consults the list first and panics on same-CPU
//! re-acquisition.
//!
//! Note that acquiring the same lock for reading is also forbidden, as another
//! CPU could acquire the lock for writing in between two read acquisitions from
//! the same CPU; this would cause the writer to wait for all readers to go away
//! while the second read acquisition would wait for all writers to leave.

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

#[cfg(target_os = "none")]
use crate::cpu::{irq_state::raw_irqs_disable, irqs_enabled, percpu::try_this_cpu};

#[cfg(not(target_os = "none"))]
extern crate std;

/// Maximum number of distinct locks a single CPU can hold simultaneously
/// while still being tracked. Acquisitions beyond this limit are silently
/// left untracked.
const MAX_HELD_LOCKS: usize = 32;

/// The mode in which a lock is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LockMode {
    /// A read hold that does not admit same-CPU re-acquisition.
    NonReentrantRead = 0,
    /// A read hold that allows same-CPU re-acquisition.
    ReentrantRead = 1,
    /// An exclusive write hold. Does not admit same-CPU re-acquisition.
    Write = 2,
}

impl From<LockMode> for u8 {
    fn from(mode: LockMode) -> Self {
        mode as Self
    }
}

impl From<u8> for LockMode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::NonReentrantRead,
            1 => Self::ReentrantRead,
            _ => Self::Write,
        }
    }
}

/// A single entry in the per-CPU list of held locks.
///
/// Note, fields are atomics, but this structure is not really safe for
/// concurrent use.
#[derive(Debug)]
struct HeldLock {
    /// Address of the lock's synchronization word, or 0 when the slot is free.
    addr: AtomicUsize,
    /// Mode in which the lock is held (a [`LockMode`]).
    mode: AtomicU8,
    /// Number of outstanding guards referencing this lock. This is greater
    /// than 1 when a guard has been split via `map_split()`.
    count: AtomicU32,
}

impl HeldLock {
    const fn empty() -> Self {
        Self {
            addr: AtomicUsize::new(0),
            mode: AtomicU8::new(0),
            count: AtomicU32::new(0),
        }
    }

    fn addr(&self) -> usize {
        self.addr.load(Ordering::Relaxed)
    }

    fn mode(&self) -> LockMode {
        self.mode.load(Ordering::Relaxed).into()
    }

    /// Claims a free slot for `addr`/`mode` with a single reference.
    fn claim(&self, addr: usize, mode: LockMode) {
        self.mode.store(mode.into(), Ordering::Relaxed);
        self.count.store(1, Ordering::Relaxed);
        self.addr.store(addr, Ordering::Relaxed);
    }

    /// Adds a reference to an already occupied slot.
    fn acquire(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Drops a reference, freeing the slot once the last one goes away.
    /// Returns `true` if the reference count reaches zero.
    fn release(&self) -> bool {
        if self.count.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.addr.store(0, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Overwrites this slot with the contents of `other`, clearing the
    /// contents of `other`.
    fn replace_with(&self, other: &Self) {
        self.mode
            .store(other.mode.load(Ordering::Relaxed), Ordering::Relaxed);
        self.count
            .store(other.count.swap(0, Ordering::Relaxed), Ordering::Relaxed);
        self.addr
            .store(other.addr.swap(0, Ordering::Relaxed), Ordering::Relaxed);
    }
}

/// Per-CPU list of currently held locks.
///
/// When the SVSM runs as a ring-0 kernel, instances of this struct
/// are embedded in [`PerCpu`](crate::cpu::percpu::PerCpu), and are
/// only accessed by the CPU that owns them.
///
/// When running on a host OS (e.g. for unit tests), the tracker lives
/// in thread-local storage. See the different versions of `with_tracker()`.
#[derive(Debug)]
pub struct LockTracker {
    locks: [HeldLock; MAX_HELD_LOCKS],
    len: AtomicUsize,
}

impl LockTracker {
    pub const fn new() -> Self {
        Self {
            locks: [const { HeldLock::empty() }; MAX_HELD_LOCKS],
            len: AtomicUsize::new(0),
        }
    }

    fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    fn iter(&self) -> impl Iterator<Item = &HeldLock> {
        self.locks.iter().take(self.len())
    }

    fn find(&self, addr: usize) -> Option<&HeldLock> {
        self.iter().find(|lock| lock.addr() == addr)
    }

    /// Mark a lock as acquired, bumping its reference count if already
    /// tracked, or inserting a new entry otherwise, if there are free slots.
    fn acquire(&self, addr: usize, mode: LockMode) {
        if let Some(lock) = self.find(addr) {
            debug_assert_eq!(lock.mode(), mode);
            lock.acquire();
        } else if let Some(lock) = self.locks.get(self.len()) {
            lock.claim(addr, mode);
            self.len.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drop one reference to the lock with the given address, removing it
    /// if the reference count drops to zero.
    fn release(&self, addr: usize) {
        let Some(idx) = self.iter().position(|lock| lock.addr() == addr) else {
            return;
        };

        let slot = &self.locks[idx];
        if !slot.release() {
            return;
        }

        // Swap-remove the freed slot, unless it was already the last one.
        let len = self.len.fetch_sub(1, Ordering::Relaxed);
        let last = len - 1;
        if idx != last {
            slot.replace_with(&self.locks[last]);
        }
    }
}

/// A guard that disables interrupts while a tracker is inspected or mutated,
/// giving the multi-field operations logical atomicity against same-CPU
/// reentrancy.
#[cfg(target_os = "none")]
struct LockTrackerGuard<'a> {
    locks: &'a LockTracker,
    irqs_enabled: bool,
}

#[cfg(target_os = "none")]
impl<'a> LockTrackerGuard<'a> {
    fn new(locks: &'a LockTracker) -> Self {
        let irqs_enabled = irqs_enabled();
        raw_irqs_disable();
        Self {
            locks,
            irqs_enabled,
        }
    }
}

#[cfg(target_os = "none")]
impl Drop for LockTrackerGuard<'_> {
    fn drop(&mut self) {
        if self.irqs_enabled {
            // Use a raw `STI` instead of `raw_irqs_enable()` to avoid
            // triggering #HV event processing, which could run arbitrary
            // IPI handlers.
            // SAFETY: we only restore the interrupt state that was in
            // effect on entry to this function.
            unsafe {
                core::arch::asm!("sti", options(att_syntax, preserves_flags, nomem));
            }
        }
    }
}

/// Computes the tracking key for a lock from its synchronization word.
#[inline]
fn lock_addr(lock: &AtomicU64) -> usize {
    core::ptr::from_ref(lock) as usize
}

/// Runs `f` against the calling CPU's tracker. Note, this disables
/// interrupts while invoking `f`.
///
/// Returns `None` (without invoking `f`) when there is no per-CPU state to
/// operate on, i.e. very early during boot or on the host test target.
#[cfg(target_os = "none")]
fn with_tracker<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&LockTracker) -> R,
{
    let cpu = try_this_cpu()?;
    let guard = LockTrackerGuard::new(cpu.lock_tracker());
    Some(f(guard.locks))
}

#[cfg(not(target_os = "none"))]
fn with_tracker<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&LockTracker) -> R,
{
    std::thread_local! {
        static TRACKER: LockTracker = const { LockTracker::new() };
    }
    TRACKER.with(|tracker| Some(f(tracker)))
}

/// Panics if the current CPU already holds `lock` in a way that would deadlock
/// with a new acquisition in the given `mode`.
///
/// This must be called *before* a blocking acquisition attempt, so that the
/// reentrancy is reported instead of hanging in the acquisition loop.
pub fn check(lock: &AtomicU64, mode: LockMode) {
    with_tracker(|locks| {
        if let Some(held) = locks.find(lock_addr(lock)) {
            let allowed = mode == LockMode::ReentrantRead && held.mode() == LockMode::ReentrantRead;
            assert!(
                allowed,
                "Detected same-CPU reentrant RWLock deadlock (already holding {held:?}, acquiring {mode:?})"
            );
        }
    });
}

/// Records that the current CPU holds `lock` in the given `mode`.
///
/// This function may be called multiple times from a single CPU for
/// the same lock, since lock references may be split
/// (see [`map_split()`](super::rwlock::RawWriteLockGuard::map_split).
pub fn record(lock: &AtomicU64, mode: LockMode) {
    with_tracker(|locks| locks.acquire(lock_addr(lock), mode));
}

/// Releases one reference to `lock` held by the current CPU.
///
/// Like `record()`, this function may be called more than once for
/// the same lock, in the case of split locks.
pub fn release(lock: &AtomicU64) {
    with_tracker(|locks| locks.release(lock_addr(lock)));
}

/// Checks that no tracked locks are held across a scheduling point.
pub fn preemption_checks() {
    with_tracker(|locks| {
        let len = locks.len();
        if len != 0 {
            panic!("Holding {len} RWLock(s) across a scheduling point");
        }
    });
}
