// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Tanish Desai
//
// Author: Tanish Desai

//! Flat single-bit atomic bitmap allocator.
//!
//! Each bit is one slot (`0` = free, `1` = used). Allocation finds a word that
//! is not all-ones, takes the complement to expose free bits, and claims the
//! first free bit with a CAS. All operations are atomic and take `&self`.
//!
//! Stable Rust cannot size `[AtomicU64; f(N)]` from one const generic, so both
//! `N` and `WORDS` are required. Prefer [`flat_bitmap_allocator!`](crate::flat_bitmap_allocator)
//! to keep them in sync.

use core::sync::atomic::{AtomicU64, Ordering};

/// Build a [`FlatBitmapAllocator`] with capacity `$n`, deriving `WORDS` automatically.
#[macro_export]
macro_rules! flat_bitmap_allocator {
    ($n:expr) => {
        $crate::utils::flat_bitmap_allocator::FlatBitmapAllocator::<
            {
                const N: usize = $n;
                N
            },
            {
                const N: usize = $n;
                N.div_ceil(64)
            },
        >
    };
}

/// Flat atomic bitmap with exactly `N` bits.
///
/// Padding bits past `N` in the last word (when `N` is not a multiple of 64)
/// are permanently marked used so they are never allocated.
#[derive(Debug)]
pub struct FlatBitmapAllocator<const N: usize, const WORDS: usize> {
    words: [AtomicU64; WORDS],
}

impl<const N: usize, const WORDS: usize> FlatBitmapAllocator<N, WORDS> {
    /// Number of allocatable bits.
    pub const CAPACITY: usize = N;

    /// Create an allocator with every bit free. Padding bits past `N` in the
    /// last word are marked used so they are never allocated.
    pub const fn new() -> Self {
        let mut words = [const { AtomicU64::new(0) }; WORDS];
        let rem = N % (u64::BITS as usize);
        if rem != 0 {
            // High bits past `N` must look "used" so alloc never returns them.
            words[WORDS - 1] = AtomicU64::new(!((1u64 << rem) - 1));
        }
        Self { words }
    }

    /// Allocate one free bit. Returns its index, or `None` if exhausted.
    pub fn alloc(&self) -> Option<usize> {
        for (word_idx, word) in self.words.iter().enumerate() {
            loop {
                let cur = word.load(Ordering::Relaxed);
                // Skip full words (no free bits).
                if cur == u64::MAX {
                    break;
                }
                // Complement: free bits become 1; first free = trailing_zeros.
                let bit = (!cur).trailing_zeros() as usize;
                let new = cur | (1u64 << bit);
                if word
                    .compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
                {
                    let idx = word_idx * (u64::BITS as usize) + bit;
                    debug_assert!(idx < N);
                    return Some(idx);
                }
                // Lost the race; retry this word.
            }
        }
        None
    }

    /// Free a previously allocated bit.
    pub fn free(&self, bit: usize) {
        assert!(bit < N);
        let word_idx = bit / (u64::BITS as usize);
        let mask = !(1u64 << (bit % (u64::BITS as usize)));
        self.words[word_idx].fetch_and(mask, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn alloc_and_free() {
        let b = <crate::flat_bitmap_allocator!(128)>::new();
        assert_eq!(b.alloc(), Some(0));
        assert_eq!(b.alloc(), Some(1));
        b.free(0);
        assert_eq!(b.alloc(), Some(0));
    }

    #[test]
    fn skips_full_words() {
        let b = <crate::flat_bitmap_allocator!(128)>::new();
        for _ in 0..64 {
            assert!(b.alloc().is_some());
        }
        assert_eq!(b.alloc(), Some(64));
    }

    #[test]
    fn exhausted() {
        let b = <crate::flat_bitmap_allocator!(64)>::new();
        for _ in 0..64 {
            assert!(b.alloc().is_some());
        }
        assert_eq!(b.alloc(), None);
    }

    #[test]
    fn partial_capacity_padding() {
        let b = <crate::flat_bitmap_allocator!(100)>::new();
        let mut n = 0;
        while b.alloc().is_some() {
            n += 1;
        }
        assert_eq!(n, 100);
        assert_eq!(b.alloc(), None);
    }
}
