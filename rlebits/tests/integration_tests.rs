//! Integration tests for RleBits
//!
//! These tests use std library features like Vec and random number generation.
//! Features 'std' and 'thread-safe' are automatically enabled for these tests.

use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
#[cfg(feature = "thread-safe")]
use rlebits::sync::ThreadSafeRleBits;
use rlebits::*;

#[test]
fn test_minimum() {
    let mut rle = RleBits::new(1, 0);
    rle.set(0, true).unwrap();
    assert_eq!(rle.sanity_check(), 2);
}

#[test]
fn test_set_range_leading_zeroes_less_than_len() {
    let mut rle = RleBits::new(10, 199);
    rle.set_range(0, 5, false).unwrap(); // No-op, but explicit
    rle.set_range(0, 7, true).unwrap();
    for i in 0..7 {
        assert_eq!(rle.get(i), Some(true));
    }
    for i in 7..10 {
        assert_eq!(rle.get(i), Some(false));
    }
    assert_eq!(rle.get_run_length(0), 0);
    assert_eq!(rle.get_run_length(1), 7);
    assert_eq!(rle.get_run_length(2), 3);
    assert_eq!(rle.sanity_check(), 3);
}

#[test]
fn test_set_over_set() {
    let mut rle = RleBits::new(100, 3);
    assert_eq!(rle.sanity_check(), 1);
    rle.set_range(50, 10, true).unwrap();
    assert_eq!(rle.sanity_check(), 3);
    rle.set_range(0, 99, true).unwrap();
    assert_eq!(rle.sanity_check(), 3);
    rle.set(0, false).unwrap();
    assert_eq!(rle.sanity_check(), 3);
    rle.set_range(0, 100, true).unwrap();
    assert_eq!(rle.sanity_check(), 2);
}

#[test]
fn test_set_bit1_then_bit0() {
    let mut rle = RleBits::new(10, 199);
    rle.set(1, true).unwrap();
    rle.set(0, true).unwrap();
    assert_eq!(rle.get(0), Some(true));
    assert_eq!(rle.get(1), Some(true));
    for i in 2..10 {
        assert_eq!(rle.get(i), Some(false));
    }
    assert_eq!(rle.get_run_length(0), 0);
    assert_eq!(rle.get_run_length(1), 2);
    assert_eq!(rle.get_run_length(2), 8);
    assert_eq!(rle.sanity_check(), 3);
}

#[test]
fn test_set_range_leading_zeroes_equal_len() {
    let mut rle = RleBits::new(10, 199);
    rle.set_range(0, 10, true).unwrap();
    for i in 0..10 {
        assert_eq!(rle.get(i), Some(true));
    }
    assert_eq!(rle.sanity_check(), 2);
}

#[test]
fn test_set_range_leading_zeroes_greater_len() {
    let mut rle = RleBits::new(10, 199);
    rle.set_range(0, 11, true).unwrap_err();
}

#[test]
fn test_randomized_set_and_get() {
    let mut rng = StdRng::seed_from_u64(42);
    let length = 100usize;
    let mut rle = RleBits::new(length, 199);
    let mut bits = vec![false; length];
    for _ in 0..500 {
        let idx = rng.random_range(0..length as u64) as usize;
        let value = rng.random_range(0..=1) != 0;
        rle.set(idx, value).unwrap();
        bits[idx] = value;
        #[allow(clippy::needless_range_loop)]
        for i in 0..length {
            assert_eq!(rle.get(i), Some(bits[i]));
        }
        rle.sanity_check();
    }
}

#[test]
fn test_randomized_set_range() {
    let mut rng = StdRng::seed_from_u64(123);
    let length = 120usize;
    let mut rle = RleBits::new(length, 199);
    let mut bits = vec![false; length];
    for _ in 0..199 {
        let start = rng.random_range(0..length as u64) as usize;
        let max_len = length - start;
        let range = if max_len == 0 {
            1
        } else {
            rng.random_range(1..=max_len as u64) as usize
        };
        let value = rng.random_range(0..=1) != 0;
        rle.set_range(start, range, value).unwrap();
        #[allow(clippy::needless_range_loop)]
        for i in start..(start + range) {
            bits[i] = value;
        }
        #[allow(clippy::needless_range_loop)]
        for i in 0..length {
            assert_eq!(rle.get(i), Some(bits[i]), "Mismatch at index {}", i);
        }
        rle.sanity_check();
    }
}

#[test]
fn test_zero_run_followed_by_nonzero_failure() {
    let mut rle = RleBits::new(36, 199);
    rle.set(35, true).unwrap();
    rle.set(34, true).unwrap();
    assert!(rle.sanity_check() == 2);

    let mut seen_zero = false;
    for i in 1..199 {
        // Check reasonable number of runs
        let run = rle.get_run_length(i);
        if run == 0 {
            seen_zero = true;
        } else if seen_zero {
            panic!("Non-zero run after zero at runs[{}]", i);
        }

        // Break if we've seen a zero and subsequent runs are all zero
        if seen_zero && run == 0 {
            // Check a few more to ensure pattern continues
            let mut all_zero = true;
            for j in (i + 1)..std::cmp::min(i + 5, 199) {
                if rle.get_run_length(j) != 0 {
                    all_zero = false;
                    break;
                }
            }
            if all_zero {
                break;
            }
        }
    }
}

proptest! {
    #[test]
    fn prop_set_get_matches(length in 1usize..100, idx in 0usize..100, value: bool) {
    let mut rle = RleBits::new(length, 199);
        if idx < length {
            rle.set(idx, value).unwrap();
            prop_assert_eq!(rle.get(idx), Some(value));
        } else {
            prop_assert_eq!(rle.get(idx), None);
        }
        rle.sanity_check();
    }

    #[test]
    fn prop_set_range_get_matches(length in 1usize..100, start in 0usize..100, range in 1usize..20, value: bool) {
    let mut rle = RleBits::new(length, 199);
        let len = if start + range > length { length.saturating_sub(start) } else { range };
        if len > 0 && start < length {
            rle.set_range(start, len, value).unwrap();
            for i in start..(start+len) {
                prop_assert_eq!(rle.get(i), Some(value));
            }
        }
        rle.sanity_check();
    }

    #[test]
    fn prop_no_zero_run_followed_by_nonzero(length in 1usize..100, ops in proptest::collection::vec((0usize..100, any::<bool>()), 1..50)) {
    let mut rle = RleBits::new(length, 199);
        for (idx, value) in ops {
            if idx < length {
                rle.set(idx, value).unwrap();
            }
        }
        let mut seen_zero = false;
        for i in 1..199 { // Check reasonable number of runs
            let run = rle.get_run_length(i);
            if run == 0 {
                seen_zero = true;
            } else if seen_zero {
                panic!("Non-zero run after zero at runs[{}]", i);
            }

            // Break early if we've found the pattern
            if seen_zero && run == 0 {
                let mut all_zero = true;
                for j in (i+1)..std::cmp::min(i+5, 199) {
                    if rle.get_run_length(j) != 0 {
                        all_zero = false;
                        break;
                    }
                }
                if all_zero {
                    break;
                }
            }
        }
    }
}

#[test]
fn test_partial_leading_ones_triggers_move_runs_up() {
    let mut rle_bits = RleBits::new(10, 199);
    rle_bits.set_range(0, 3, true).unwrap();
    for i in 0..3 {
        assert_eq!(rle_bits.get(i), Some(true));
    }
    for i in 3..10 {
        assert_eq!(rle_bits.get(i), Some(false));
    }
    assert_eq!(rle_bits.sanity_check(), 3);
}

/*
#[test]
fn test_runs_array_overflow() {
    let n = 250;
    let mut rle_bits = RleBits::new(n, 3);
    let mut got_error = false;
    for i in 0..n {
        let res = rle_bits.set(i, (i % 2) == 1);
        if res.is_err() {
            got_error = true;
            break;
        }
    }
    assert!(
        got_error,
        "Should have returned an error due to runs array overflow"
    );
}
*/

#[test]
fn test_sequential_set_all_ones() {
    let mut rle_bits = RleBits::new(32, 199);
    for i in 0..32 {
        rle_bits.set(i, true).unwrap();
        assert_eq!(rle_bits.get(i), Some(true));
        for j in 0..=i {
            assert_eq!(rle_bits.get(j), Some(true));
        }
        for j in (i + 1)..32 {
            assert_eq!(rle_bits.get(j), Some(false));
        }
        rle_bits.sanity_check();
    }
    assert_eq!(rle_bits.sanity_check(), 2);
}

#[test]
fn test_sequential_set_alternate() {
    let mut rle_bits = RleBits::new(16, 199);
    for i in 0..16 {
        rle_bits.set(i, (i % 2) == 1).unwrap();
        assert_eq!(rle_bits.get(i), Some((i % 2) == 1));
        rle_bits.sanity_check();
    }
    for i in 0..16 {
        assert_eq!(rle_bits.get(i), Some((i % 2) == 1));
    }
}

#[test]
fn test_sequential_set_flip_flop() {
    let mut rle_bits = RleBits::new(8, 199);
    for i in 0..8 {
        rle_bits.set(i, true).unwrap();
        assert_eq!(rle_bits.get(i), Some(true));
        rle_bits.sanity_check();
    }
    for i in 0..8 {
        rle_bits.set(i, false).unwrap();
        assert_eq!(rle_bits.get(i), Some(false));
        rle_bits.sanity_check();
    }
    assert_eq!(rle_bits.sanity_check(), 1);
}

#[test]
fn test_sanity() {
    let rle_bits = RleBits::new(100, 199);
    assert_eq!(rle_bits.sanity_check(), 1);
    assert_eq!(rle_bits.get(99), Some(false));
    assert_eq!(rle_bits.get(100), None);
}

#[test]
fn test_all_ones() {
    let mut rle_bits = RleBits::new(50, 199);
    rle_bits.set_range(0, 50, true).unwrap();
    for i in 0..50 {
        assert_eq!(rle_bits.get(i), Some(true));
    }
    assert_eq!(rle_bits.sanity_check(), 2);
}

#[test]
fn test_all_zeroes() {
    let rle_bits = RleBits::new(50, 199);
    for i in 0..50 {
        assert_eq!(rle_bits.get(i), Some(false));
    }
    assert_eq!(rle_bits.sanity_check(), 1);
}

#[test]
fn test_toggle_bits() {
    let mut rle_bits = RleBits::new(10, 199);
    for i in 0..10 {
        rle_bits.set(i, true).unwrap();
        assert_eq!(rle_bits.get(i), Some(true));
        rle_bits.set(i, false).unwrap();
        assert_eq!(rle_bits.get(i), Some(false));
    }
    assert_eq!(rle_bits.sanity_check(), 1);
}

#[test]
fn test_set_range_edges() {
    let mut rle_bits = RleBits::new(20, 199);
    rle_bits.set_range(0, 5, true).unwrap();
    rle_bits.set_range(15, 5, true).unwrap();
    for i in 0..5 {
        assert_eq!(rle_bits.get(i), Some(true));
    }
    for i in 5..15 {
        assert_eq!(rle_bits.get(i), Some(false));
    }
    for i in 15..20 {
        assert_eq!(rle_bits.get(i), Some(true));
    }
    assert_eq!(rle_bits.sanity_check(), 4);
}

#[test]
fn test_set_range_middle() {
    let mut rle_bits = RleBits::new(20, 199);
    rle_bits.set_range(7, 6, true).unwrap();
    for i in 0..7 {
        assert_eq!(rle_bits.get(i), Some(false));
    }
    for i in 7..13 {
        assert_eq!(rle_bits.get(i), Some(true));
    }
    for i in 13..20 {
        assert_eq!(rle_bits.get(i), Some(false));
    }
    assert_eq!(rle_bits.sanity_check(), 3);
}

#[test]
fn test_set_range_overlapping() {
    let mut rle_bits = RleBits::new(30, 199);
    rle_bits.set_range(5, 10, true).unwrap();
    rle_bits.set_range(10, 10, false).unwrap();
    for i in 0..5 {
        assert_eq!(rle_bits.get(i), Some(false));
    }
    for i in 5..10 {
        assert_eq!(rle_bits.get(i), Some(true));
    }
    for i in 10..20 {
        assert_eq!(rle_bits.get(i), Some(false));
    }
    for i in 20..30 {
        assert_eq!(rle_bits.get(i), Some(false));
    }
    assert!(rle_bits.sanity_check() <= 4);
}

#[test]
fn test_large_range() {
    let mut rle_bits = RleBits::new(150, 199);
    rle_bits.set_range(50, 50, true).unwrap();
    for i in 0..50 {
        assert_eq!(rle_bits.get(i), Some(false));
    }
    for i in 50..100 {
        assert_eq!(rle_bits.get(i), Some(true));
    }
    for i in 100..150 {
        assert_eq!(rle_bits.get(i), Some(false));
    }
    assert_eq!(rle_bits.sanity_check(), 3);
}

#[test]
fn test_invalid_index() {
    let rle_bits = RleBits::new(10, 199);
    assert_eq!(rle_bits.get(10), None);
    assert_eq!(rle_bits.get(100), None);
}

#[test]
fn test_set_range_out_of_bounds() {
    let mut rle_bits = RleBits::new(10, 199);
    rle_bits.set_range(5, 10, true).unwrap_err();
}

#[test]
fn test_set_invalid_value() {
    // This test is no longer relevant since bool values can only be true/false
    // Keeping the test structure but making it a no-op
    let _rle_bits = RleBits::new(10, 199);
    // With bool values, there are no invalid values to test
}

#[test]
fn test_leading_one() {
    let mut rle_bits = RleBits::new(100, 199);
    rle_bits.set(0, true).unwrap();
    assert!(rle_bits.get(2) == Some(false));
    assert!(rle_bits.get(0) == Some(true));
    assert!(rle_bits.get(4) == Some(false));
    assert!(rle_bits.sanity_check() == 3);
    rle_bits.set(0, false).unwrap();
    assert!(rle_bits.sanity_check() == 1);
}

#[test]
fn test_set_bit3() {
    let mut rle_bits = RleBits::new(100, 199);
    rle_bits.set(3, true).unwrap();
    assert!(rle_bits.get(2) == Some(false));
    assert!(rle_bits.get(3) == Some(true));
    assert!(rle_bits.get(4) == Some(false));
    assert!(rle_bits.sanity_check() == 3);
}

#[test]
fn test_set_bit99() {
    let mut rle_bits = RleBits::new(100, 199);
    rle_bits.set(99, true).unwrap();
    assert!(rle_bits.get(98) == Some(false));
    assert!(rle_bits.get(99) == Some(true));
    assert!(rle_bits.get(100).is_none());
    assert!(rle_bits.sanity_check() == 2);
}

#[test]
fn test_set_bits3and4() {
    let mut rle_bits = RleBits::new(100, 199);
    rle_bits.set(3, true).unwrap();
    rle_bits.set(4, true).unwrap();
    assert!(rle_bits.get(2) == Some(false));
    assert!(rle_bits.get(3) == Some(true));
    assert!(rle_bits.get(4) == Some(true));
    assert!(rle_bits.get(5) == Some(false));
    assert!(rle_bits.sanity_check() == 3);
}

#[test]
fn test_set_bit3for2() {
    let mut rle_bits = RleBits::new(100, 199);
    rle_bits.set_range(3, 2, true).unwrap();
    assert!(rle_bits.get(2) == Some(false));
    assert!(rle_bits.get(3) == Some(true));
    assert!(rle_bits.get(4) == Some(true));
    assert!(rle_bits.get(5) == Some(false));
    assert!(rle_bits.sanity_check() == 3);
    rle_bits.set(3, false).unwrap();
    assert!(rle_bits.sanity_check() == 3);
    rle_bits.set(4, false).unwrap();
    assert!(rle_bits.sanity_check() == 1);
}

#[test]
fn test_set_bit9for2() {
    let mut rle_bits = RleBits::new(100, 199);
    rle_bits.set_range(9, 2, true).unwrap();
    rle_bits.set_range(13, 2, true).unwrap();
    assert!(rle_bits.get(8) == Some(false));
    assert!(rle_bits.get(9) == Some(true));
    assert!(rle_bits.get(10) == Some(true));
    assert!(rle_bits.get(11) == Some(false));
    assert!(rle_bits.get(12) == Some(false));
    assert!(rle_bits.get(13) == Some(true));
    assert!(rle_bits.get(14) == Some(true));
    assert!(rle_bits.get(15) == Some(false));
    assert!(rle_bits.sanity_check() == 5);
    rle_bits.set_range(7, 25, false).unwrap();
    assert!(rle_bits.sanity_check() == 1);
}

#[test]
fn test_reverse_order_corruption_bug() {
    // This test sets every other bit starting from bit 998 down to 0
    // and runs sanity_check after each set() to detect corruption

    let mut rle = RleBits::new(1000, 30);

    println!("Setting every other bit from 998 down to 0...");

    for bit in (0..500).rev().map(|i| i * 2) {
        match rle.set(bit, true) {
            Ok(()) => {
                // Run sanity check after each set operation
                // This should panic if the structure becomes corrupted
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rle.sanity_check()))
                {
                    Ok(_) => {
                        // Sanity check passed, continue
                    }
                    Err(_) => {
                        println!(
                            "CORRUPTION DETECTED: Sanity check failed after setting bit {}",
                            bit
                        );
                        panic!("sanity_check() assertion failed - structure corrupted!");
                    }
                }
            }
            Err(RleBitsError::RunsOutOfSpace) => {
                println!(
                    "RunsOutOfSpace error at bit {} - this is expected behavior",
                    bit
                );
                break;
            }
            Err(e) => {
                panic!("Unexpected error at bit {}: {:?}", bit, e);
            }
        }
    }

    println!("Test completed without corruption detected");
}

// Thread-safe tests using the no_std compatible ThreadSafeRleBits
#[cfg(feature = "thread-safe")]
mod thread_safe_tests {
    #[test]
    fn test_thread_safe_reset() {
        let rle = ThreadSafeRleBits::new(10, 199);
        rle.set_range(0, 10, true).unwrap();
        for i in 0..10 {
            assert_eq!(rle.get(i), Some(true));
        }
        rle.reset();
        for i in 0..10 {
            assert_eq!(rle.get(i), Some(false));
        }
    }

    #[test]
    fn test_rwlock_reset() {
        use rlebits::sync::RwLockRleBits;
        let rle = RwLockRleBits::new(10, 199);
        rle.set_range(0, 10, true).unwrap();
        for i in 0..10 {
            assert_eq!(rle.get(i), Some(true));
        }
        rle.reset();
        for i in 0..10 {
            assert_eq!(rle.get(i), Some(false));
        }
    }

    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_thread_safe_basic_operations() {
        let rle = ThreadSafeRleBits::new(100, 199);

        // Test basic operations
        assert_eq!(rle.get(0), Some(false));
        rle.set(5, true).unwrap();
        assert_eq!(rle.get(5), Some(true));

        rle.set_range(10, 5, true).unwrap();
        for i in 10..15 {
            assert_eq!(rle.get(i), Some(true));
        }

        assert_eq!(rle.sanity_check(), 5);
    }

    #[test]
    fn test_multi_threaded_access() {
        let rle = Arc::new(ThreadSafeRleBits::new(1000, 199));
        let mut handles = vec![];

        // Spawn multiple threads that modify different ranges
        for thread_id in 0..4 {
            let rle_clone = Arc::clone(&rle);
            let handle = thread::spawn(move || {
                let start = thread_id * 250;
                let end = start + 250;

                // Each thread sets its range to 1
                rle_clone.set_range(start, 250, true).unwrap();

                // Verify the range was set correctly
                for i in start..end {
                    assert_eq!(rle_clone.get(i), Some(true));
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify the entire range is set to 1
        for i in 0..1000 {
            assert_eq!(rle.get(i), Some(true));
        }
    }

    #[test]
    fn test_concurrent_read_write() {
        let rle = Arc::new(ThreadSafeRleBits::new(100, 199));
        let mut handles = vec![];

        // Writer thread
        let rle_writer = Arc::clone(&rle);
        let writer_handle = thread::spawn(move || {
            for i in 0..100 {
                rle_writer.set(i, true).unwrap();
            }
        });
        handles.push(writer_handle);

        // Reader threads
        for _ in 0..3 {
            let rle_reader = Arc::clone(&rle);
            let reader_handle = thread::spawn(move || {
                for _ in 0..100 {
                    // Just read values, don't care about the specific result
                    // since writes might be in progress
                    for i in 0..100 {
                        rle_reader.get(i);
                    }
                }
            });
            handles.push(reader_handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // After all threads complete, all bits should be 1
        for i in 0..100 {
            assert_eq!(rle.get(i), Some(true));
        }
    }

    #[test]
    fn test_with_lock_atomicity() {
        let rle = Arc::new(ThreadSafeRleBits::new(100, 199));

        // Use with_lock to perform multiple operations atomically
        let result = rle.with_lock(|bits| {
            bits.set_range(10, 20, true).unwrap();
            bits.set_range(30, 20, true).unwrap();
            bits.sanity_check()
        });

        assert_eq!(result, 3); // Should be 3 runs: 0s[0-9], 1s[10-49], 0s[50-99]

        // Verify the operations were atomic
        for i in 10..30 {
            assert_eq!(rle.get(i), Some(true));
        }
        for i in 30..50 {
            assert_eq!(rle.get(i), Some(true));
        }
    }

    #[test]
    fn test_stress_concurrent_modifications() {
        let rle = Arc::new(ThreadSafeRleBits::new(1000, 199));
        let mut handles = vec![];

        // Multiple threads modifying overlapping ranges
        for thread_id in 0..8 {
            let rle_clone = Arc::clone(&rle);
            let handle = thread::spawn(move || {
                let mut rng = StdRng::seed_from_u64(thread_id as u64);

                for _ in 0..100 {
                    let start = rng.random_range(0..900);
                    let len = rng.random_range(1..100);
                    let value = rng.random_range(0..2) != 0;

                    // Just perform the operation - don't verify during concurrent access
                    // as other threads might be modifying the same ranges
                    let _ = rle_clone.set_range(start, len, value);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // The final state should be consistent
        let final_sanity = rle.sanity_check();
        assert!(final_sanity > 0, "Sanity check should pass");

        // Verify internal consistency by checking that all bits can be read
        for i in 0..1000 {
            assert!(rle.get(i).is_some(), "Should be able to read all positions");
        }
    }
}
