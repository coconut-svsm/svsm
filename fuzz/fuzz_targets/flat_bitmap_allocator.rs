// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 Tanish Desai
//
// Author: Tanish Desai

//! Correctness fuzzer for [`svsm::utils::flat_bitmap_allocator::FlatBitmapAllocator`].
//!
//! Sequential runs compare every `alloc` / `free` against a shadow bitmap.
//! Concurrent runs check that CAS allocation never hands the same bit to two
//! threads.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::sync::Mutex;
use svsm::utils::flat_bitmap_allocator::FlatBitmapAllocator;

#[derive(Arbitrary, Debug)]
enum Action {
    /// Allocate one bit.
    Alloc,
    /// Free the live allocation at this index (modulo the live list).
    Free(usize),
}

/// Sequential model: `alloc` returns the lowest free index, never a padding
/// bit, and matches the shadow bitmap after every operation.
fn sequential<const N: usize, const WORDS: usize>(actions: &[Action]) {
    const {
        assert!(WORDS == N.div_ceil(64), "WORDS must be N.div_ceil(64)");
    }
    let b = FlatBitmapAllocator::<N, WORDS>::new();
    let mut used = [false; N];
    let mut live: Vec<usize> = Vec::new();

    assert_eq!(FlatBitmapAllocator::<N, WORDS>::CAPACITY, N);

    for action in actions {
        match action {
            Action::Alloc => {
                let expected = used.iter().position(|&u| !u);
                let got = b.alloc();
                assert_eq!(got, expected, "alloc must return the lowest free bit");
                if let Some(idx) = got {
                    assert!(idx < N, "allocated padding or out-of-range bit {idx}");
                    assert!(!used[idx], "double alloc of bit {idx}");
                    used[idx] = true;
                    live.push(idx);
                }
            }
            Action::Free(i) => {
                if live.is_empty() {
                    continue;
                }
                let idx = live.swap_remove(*i % live.len());
                assert!(used[idx]);
                b.free(idx);
                used[idx] = false;
            }
        }
    }

    let remaining = used.iter().filter(|&&u| !u).count();
    let mut got = 0;
    let mut seen = [false; N];
    while let Some(idx) = b.alloc() {
        assert!(idx < N, "allocated padding bit {idx} while draining");
        assert!(!seen[idx], "duplicate bit {idx} while draining");
        assert!(!used[idx], "drained a still-shadow-used bit {idx}");
        seen[idx] = true;
        got += 1;
    }
    assert_eq!(got, remaining);
    assert_eq!(
        b.alloc(),
        None,
        "allocator not exhausted after filling N bits"
    );
}

/// Concurrent uniqueness: each successful `alloc` must claim a distinct bit.
/// Threads only free bits they own.
fn concurrent<const N: usize, const WORDS: usize>(actions: &[Action]) {
    const {
        assert!(WORDS == N.div_ceil(64), "WORDS must be N.div_ceil(64)");
    }
    if actions.is_empty() {
        return;
    }

    let b = FlatBitmapAllocator::<N, WORDS>::new();
    let claimed = Mutex::new([false; N]);
    let n_threads = 2 + actions.len() % 3;
    let chunk_size = actions.len().div_ceil(n_threads).max(1);

    std::thread::scope(|s| {
        let b = &b;
        let claimed = &claimed;
        for chunk in actions.chunks(chunk_size) {
            s.spawn(move || {
                let mut live: Vec<usize> = Vec::new();
                for action in chunk {
                    match action {
                        Action::Alloc => {
                            if let Some(idx) = b.alloc() {
                                assert!(idx < N, "allocated padding bit {idx}");
                                {
                                    let mut c = claimed.lock().unwrap();
                                    assert!(!c[idx], "two threads allocated bit {idx}");
                                    c[idx] = true;
                                }
                                live.push(idx);
                            }
                        }
                        Action::Free(i) => {
                            if live.is_empty() {
                                continue;
                            }
                            let idx = live.swap_remove(*i % live.len());
                            // Drop the claim before freeing so another thread
                            // cannot observe a stale claim after it reallocates.
                            {
                                let mut c = claimed.lock().unwrap();
                                assert!(c[idx]);
                                c[idx] = false;
                            }
                            b.free(idx);
                        }
                    }
                }
            });
        }
    });

    let c = claimed.lock().unwrap();
    let remaining = c.iter().filter(|&&claim| !claim).count();

    let mut got = 0;
    let mut seen = [false; N];
    while let Some(idx) = b.alloc() {
        assert!(idx < N);
        assert!(!seen[idx]);
        assert!(!c[idx]);
        seen[idx] = true;
        got += 1;
    }
    assert_eq!(got, remaining);
    assert_eq!(b.alloc(), None);
}

fuzz_target!(|actions: Vec<Action>| {
    // Exact word, partial last word, and tiny capacities.
    sequential::<1, 1>(&actions);
    sequential::<63, 1>(&actions);
    sequential::<64, 1>(&actions);
    sequential::<65, 2>(&actions);
    sequential::<100, 2>(&actions);
    sequential::<128, 2>(&actions);

    // CAS races on a partial last word and on two full words.
    concurrent::<100, 2>(&actions);
    concurrent::<128, 2>(&actions);
});
