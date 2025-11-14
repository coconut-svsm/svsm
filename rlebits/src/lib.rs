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

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

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
    /// Alternating run lengths, starting with 0s at index 0
    runs: Vec<usize>,
    /// Upper limit of values, exclusive (ie, 0-9 is represented by 10)
    limit: usize,
    /// Maximum runs index currently in use
    max_run: usize,
}

impl RleBits {
    pub fn new(limit: usize, mut size: usize) -> Self {
        if size < 10 {
            size = 10;
        }
        let mut runs = vec![0usize; size];
        runs[0] = limit;
        RleBits {
            runs,
            limit,
            max_run: 0,
        }
    }

    pub fn reset(&mut self) {
        self.runs[0] = self.limit;
        for i in 1..self.runs.len() {
            self.runs[i] = 0;
        }
        self.max_run = 0;
    }

    pub fn get(&self, index: usize) -> Option<bool> {
        if index >= self.limit {
            return None;
        }

        for (i, &next) in self.runs.iter().enumerate() {
            if index < next {
                return Some((i % 2) == 1);
            }
        }

        unreachable!("RleBits::get() - fell through all runs");
    }

    pub fn get_run_length(&self, n: usize) -> usize {
        if n > self.max_run {
            return 0;
        }

        if n == 0 {
            return self.runs[0];
        }

        self.runs[n] - self.runs[n - 1]
    }

    pub fn set(&mut self, index: usize, value: bool) -> Result<(), RleBitsError> {
        self.set_range(index, 1, value)
    }

    fn move_runs_up(&mut self, start: usize, count: usize) -> Result<(), RleBitsError> {
        let required = self.max_run + count + 1;
        if required >= self.runs.len() {
            // Try to double the size...
            let new_size = required * 2;
            match self.runs.try_reserve(new_size - self.runs.len()) {
                Ok(()) => self.runs.resize(new_size, 0),
                Err(_) => return Err(RleBitsError::RunsOutOfSpace),
            }
        }
        self.runs
            .copy_within(start..self.max_run + 1, start + count);
        for i in start..start + count {
            self.runs[i] = 0;
        }
        self.max_run += count;
        Ok(())
    }

    fn move_runs_down(&mut self, start: usize, count: usize) {
        let end = self.max_run + count;
        self.runs.copy_within(start + count..end, start);
        for i in end - count..end {
            self.runs[i] = 0;
        }
        self.max_run -= count;
    }

    pub fn set_range(
        &mut self,
        mut index: usize,
        mut len: usize,
        value: bool,
    ) -> Result<(), RleBitsError> {
        if (index.checked_add(len).is_none()) || (index + len > self.limit) {
            return Err(RleBitsError::RangeExceedsLength);
        }

        // Find the first existing run that includes the range
        let mut start = 0usize;
        let mut i = 0;
        while len > 0 && i <= self.max_run {
            let next = self.runs[i]; // Past the end of the current run
            if index < next {
                // Overlap between the range and the current run
                if ((i & 0x1) == 1) == value {
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
                            return Ok(());
                        }
                        // index + len >= next...
                        // We can squeeze out the current wrong-value run
                        // since it is completely obliterated by the range
                        // Detect case where we are squeezing out the last run
                        if i == self.max_run {
                            self.max_run -= 1;
                            self.runs[i] = 0;
                            self.runs[i - 1] = self.limit;
                            return Ok(());
                        } else {
                            self.move_runs_down(i - 1, 2);
                        }
                        i -= 1; // repeat analysis of newly expanded prior run
                        continue;
                    }

                    // Special case for index == start (== 0) && i == 0 && value == true
                    // Since runs[0] represents false values, in this case we need
                    // to set runs[0] = 0.
                    debug_assert!(index == 0 && start == 0 && i == 0 && value);
                    if next <= len {
                        self.runs[0] = 0;
                        if self.max_run == 0 {
                            // If max_run=0, then everything was false. Therefore,
                            // len MUST == next == limit. So flip all the bits!
                            self.max_run = 1;
                            self.runs[1] = self.limit;
                            return Ok(());
                        }
                        // We may not have set ALL the bits... need to keep checking
                        len -= next;
                        if len == 0 {
                            return Ok(());
                        }
                        index = next;
                        i = 1;
                        continue;
                    } else {
                        // len < next... so we need to insert a new pair of runs.
                        self.move_runs_up(0, 2)?;
                        self.runs[1] = len;
                        return Ok(());
                    }
                }

                // index != start, so need to leave some bits at the beginning the same
                if index + len < next {
                    // range is entirely within existing, wrong-valued run. Split it.
                    self.move_runs_up(i, 2)?;
                    self.runs[i] = index;
                    self.runs[i + 1] = index + len;
                    return Ok(());
                } else {
                    // range spans beyond end of current run
                    // Shift items from end of current run to next run
                    self.runs[i] = index;
                    if i == self.max_run {
                        // i.e., self.runs[i+1] is 0
                        self.max_run += 1;
                        self.runs[i + 1] = self.limit;
                        return Ok(());
                    }
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
        let mut runs = 0;
        let mut next = 0;
        for i in 1..self.runs.len() {
            assert!(
                i > self.max_run || self.runs[i] > next,
                "Runs out of sequence!"
            );
            next = self.runs[i];
            if self.runs[i] != 0 {
                assert!(!flag, "Non-zero value after zero seen!");
            } else if !flag {
                flag = true;
                runs = i;
            }
        }
        assert!(self.runs[self.max_run] == self.limit, "Last run != limit!");
        assert!(runs == self.max_run + 1, "Run count incorrect!");
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
            let run_len = self.get_run_length(i);
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
