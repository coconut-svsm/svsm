// SPDX-License-Identifier: MIT
//
// Copyright (c) 2025 Advanced Micro Devices, Inc.
//
//! RleBits - A run-length encoded bit array implementation
//!
//! This crate provides a space-efficient way to store and manipulate bit arrays
//! using run-length encoding. It's particularly useful when dealing with sparse
//! bit patterns or when memory usage is a concern.
//! The range of indices is specified when the instance is initialized with new().
//! The number of contiguous runs of 0 or 1 is hard-coded in the struct RleBits,
//! but can be changed to fit the circumstances. All bits are 0 after new().
//! Performance is related to number of runs, not range.
//!
//! ## Thread Safety
//!
//! The `sync` module (when the `thread-safe` feature is enabled) provides multiple
//! thread-safe synchronization strategies optimized for different access patterns:
//!
//! - `ThreadSafeRleBits` - Simple mutex-based synchronization
//! - `RwLockRleBits` - Read-write locks for read-heavy workloads  
//!
//! See the `sync` module documentation for detailed performance characteristics.

#![cfg_attr(not(any(feature = "std", test)), no_std)]

// Synchronization primitives for thread-safe RleBits variants
#[cfg(feature = "thread-safe")]
pub mod sync;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RleBitsError {
    RangeExceedsLength,
    InvalidValue,
    RunsOutOfSpace,
    InternalError,
    #[cfg(feature = "thread-safe")]
    LockPoisoned,
}

#[derive(Debug, Clone)]
pub struct RleBits {
    runs: [usize; 199], // Alternating run lengths, starting with 0s at index 0
    length: usize,      // Upper limit of values, exclusive (ie, 0-9 is represented by 10)
}

impl RleBits {
    pub const fn new(limit: usize) -> Self {
        let mut runs = [0usize; 199];
        runs[0] = limit;
        RleBits {
            runs,
            length: limit,
        }
    }

    pub fn reset(&mut self) {
        self.runs[0] = self.length;
        for i in 1..self.runs.len() {
            self.runs[i] = 0;
        }
    }

    pub fn get(&self, index: usize) -> Option<u8> {
        if index >= self.length {
            return None;
        }

        let mut start = 0usize;
        for (i, &len) in self.runs.iter().enumerate() {
            if index < start + len {
                return Some((i % 2) as u8);
            }
            start += len;
        }

        None // Should NEVER happen
    }

    pub fn get_run(&self, n: usize) -> usize {
        if n >= self.runs.len() {
            return 0;
        }
        self.runs[n]
    }

    pub fn set(&mut self, index: usize, value: u8) -> Result<(), RleBitsError> {
        self.set_range(index, 1, value)
    }

    fn move_runs_up(&mut self, start: usize, count: usize) -> Result<(), RleBitsError> {
        let len = self.runs.len();
        if start + count >= len {
            return Err(RleBitsError::RunsOutOfSpace);
        }
        let copy_len = len - count;
        self.runs.copy_within(start..copy_len, start + count);
        for i in start..start + count {
            self.runs[i] = 0;
        }
        Ok(())
    }

    fn move_runs_down(&mut self, start: usize, count: usize) {
        let len = self.runs.len();
        self.runs.copy_within(start + count..len, start);
        for i in len - count..len {
            self.runs[i] = 0;
        }
    }

    pub fn set_range(
        &mut self,
        mut index: usize,
        mut len: usize,
        value: u8,
    ) -> Result<(), RleBitsError> {
        if (index.checked_add(len).is_none()) || (index + len > self.length) {
            return Err(RleBitsError::RangeExceedsLength);
        }
        if value != 0 && value != 1 {
            return Err(RleBitsError::InvalidValue);
        }

        // Find the first existing run that includes the range
        let mut start = 0usize;
        let mut i = 0;
        while len > 0 && i < self.runs.len() {
            let run_len = self.runs[i];
            let next = start + run_len; // Past the end of the current run
            if index < next {
                // Overlap between the range and the current run
                if (i & 0x1) == value.into() {
                    // The current run has the same value as the desired range
                    if index + len <= next {
                        // Entire range is within this run
                        return Ok(());
                    }

                    // Reduce the range and move to the next run
                    len -= next - index;
                    index = next;
                    start = next;
                    i += 1;
                    continue;
                }

                // Current run is wrong value and overlaps with the range
                // If index == start, then we can merge with the prior run
                if index == start {
                    // If there IS a prior run...
                    if i != 0 {
                        if index + len < next {
                            // We can shift len items to the prior run
                            self.runs[i - 1] += len;
                            self.runs[i] -= len;
                            return Ok(());
                        }
                        // index + len >= next...
                        // We can squeeze out the current wrong-value run
                        // since it is completely obliterated by the range
                        let merged_bits = self.runs[i] + self.runs[i + 1];
                        start -= self.runs[i - 1];
                        self.runs[i - 1] += merged_bits;
                        self.move_runs_down(i, 2);
                        i -= 1; // repeat analysis of newly expanded prior run
                        continue;
                    }

                    // Special case for index == start (== 0) && i == 0 && value != 0
                    if i != 0 || value == 0 || start != 0 || index != 0 {
                        return Err(RleBitsError::InternalError);
                    }
                    let zeroes = self.runs[0];
                    if zeroes <= len {
                        self.runs[0] = 0;
                        self.runs[1] += zeroes;
                        i = 1;
                        continue;
                    } else {
                        self.move_runs_up(0, 2)?; // Creates runs[0] = 0, moves everything else higher
                        self.runs[0] = 0;
                        self.runs[1] = len;
                        self.runs[2] -= len;
                        return Ok(());
                    }
                }

                // index != start, but index < next, so need to split current run
                if index + len < next {
                    // range is entirely within existing run
                    self.move_runs_up(i, 2)?;
                    self.runs[i] = index - start;
                    self.runs[i + 1] = len;
                    self.runs[i + 2] -= index - start + len;
                    return Ok(());
                } else {
                    // range spans beyond end of current run
                    // Shift items from end of current run to next run
                    let shift_amount = next - index;
                    self.runs[i] -= shift_amount;
                    self.runs[i + 1] += shift_amount;
                    start = index;
                    i += 1;
                    continue;
                }
            }

            i += 1;
            start = next;
        }
        // This should NEVER happen!
        Err(RleBitsError::InternalError)
    }

    // Returns the number of runs used
    pub fn sanity_check(&self) -> usize {
        let mut flag = false;
        let mut length = self.runs[0];
        let mut runs = 0;
        for i in 1..self.runs.len() {
            if self.runs[i] != 0 {
                length += self.runs[i];
                assert!(!flag, "Non-zero value after zero seen!");
            } else if !flag {
                flag = true;
                runs = i;
            }
        }
        assert!(length == self.length, "Run lengths don't add up!");
        runs
    }

    #[cfg(any(feature = "std", test))]
    pub fn dump_with<F>(&self, format_addr: F)
    where
        F: Fn(usize) -> std::string::String,
    {
        let runs = self.sanity_check();
        std::println!("Bitmap runs = {}", runs);
        let mut start = 0;
        for i in 0..runs {
            let run_len = self.get_run(i);
            std::println!(
                "Run {}: start = {}, len = {}",
                i,
                format_addr(start),
                run_len
            );
            start += run_len;
        }
    }
}
