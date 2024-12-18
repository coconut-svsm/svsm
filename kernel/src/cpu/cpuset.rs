// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use core::sync::atomic::{AtomicU64, Ordering};

/// Represents a set of CPUs, based on CPU index.  A maximum of 1024 CPUs can
/// be represented.
#[derive(Copy, Clone, Debug, Default)]
pub struct CpuSet {
    bitmask: [u64; 16],
}

impl CpuSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a CPU to the set.
    ///
    /// * `cpu_index`: the index of the CPU to add to the set.
    pub fn add(&mut self, cpu_index: usize) {
        self.bitmask[cpu_index >> 6] |= 1u64 << (cpu_index & 0x3F);
    }

    /// Removes a CPU from the set.
    ///
    /// * `cpu_index`: the index of the CPU to remove from the set.
    pub fn remove(&mut self, cpu_index: usize) {
        self.bitmask[cpu_index >> 6] &= !(1u64 << (cpu_index & 0x3F));
    }

    /// Produces an iterator to iterate over the set.
    pub fn iter(&self) -> CpuSetIterator<'_> {
        CpuSetIterator::new(self)
    }
}

#[derive(Debug)]
pub struct CpuSetIterator<'a> {
    cpu_set: &'a CpuSet,
    current_mask: u64,
    mask_index: usize,
}

impl<'a> CpuSetIterator<'a> {
    fn new(cpu_set: &'a CpuSet) -> Self {
        Self {
            cpu_set,
            current_mask: cpu_set.bitmask[0],
            mask_index: 0,
        }
    }
}

impl Iterator for CpuSetIterator<'_> {
    type Item = usize;
    fn next(&mut self) -> Option<usize> {
        while self.current_mask == 0 {
            self.mask_index += 1;
            if self.mask_index == self.cpu_set.bitmask.len() {
                return None;
            }

            self.current_mask = self.cpu_set.bitmask[self.mask_index];
        }

        let index = self.current_mask.trailing_zeros();
        self.current_mask &= !(1u64 << index);
        Some((self.mask_index << 6) | index as usize)
    }
}

/// Represents a set of CPUs, based on CPU index, which supports atomic
/// addition and removal.  A maximum of 1024 CPUs can be represented.
#[derive(Debug, Default)]
pub struct AtomicCpuSet {
    bitmask: [AtomicU64; 16],
}

impl AtomicCpuSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a CPU to the set.
    ///
    /// * `cpu_index`: the index of the CPU to add to the set.
    /// * `ordering`: the atomic ordering rules to be used when adding the CPU.
    pub fn add(&self, cpu_index: usize, ordering: Ordering) {
        self.bitmask[cpu_index >> 6].fetch_or(1u64 << (cpu_index & 0x3F), ordering);
    }

    /// Removes a CPU from the set.
    ///
    /// * `cpu_index`: the index of the CPU to remove from the set.
    /// * `ordering`: the atomic ordering rules to be used when adding the CPU.
    pub fn remove(&self, cpu_index: usize, ordering: Ordering) {
        self.bitmask[cpu_index >> 6].fetch_and(!(1u64 << (cpu_index & 0x3F)), ordering);
    }

    /// Produces an iterator to iterate over the set.  This iterator consumes
    /// the set, so the action of iterating will remove all items from the set.
    /// Items added while iteration is underway may or may not be observed by
    /// the iterator.
    ///
    /// * `ordering` - The memory ordering to apply as elements are removed
    ///   from the set.
    pub fn iter(&self, ordering: Ordering) -> AtomicCpuSetIterator<'_> {
        AtomicCpuSetIterator::new(self, ordering)
    }
}

impl Clone for AtomicCpuSet {
    fn clone(&self) -> Self {
        let clone = AtomicCpuSet::new();
        for (i, mask) in self.bitmask.iter().enumerate() {
            clone.bitmask[i].store(mask.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        clone
    }
}

#[derive(Debug)]
pub struct AtomicCpuSetIterator<'a> {
    cpu_set: &'a AtomicCpuSet,
    ordering: Ordering,
    mask_index: usize,
}

impl<'a> AtomicCpuSetIterator<'a> {
    fn new(cpu_set: &'a AtomicCpuSet, ordering: Ordering) -> Self {
        Self {
            cpu_set,
            ordering,
            mask_index: 0,
        }
    }
}

impl Iterator for AtomicCpuSetIterator<'_> {
    type Item = usize;
    fn next(&mut self) -> Option<usize> {
        while self.mask_index < self.cpu_set.bitmask.len() {
            let mask = self.cpu_set.bitmask[self.mask_index].load(Ordering::Relaxed);
            if mask != 0 {
                let index = mask.trailing_zeros();
                let cpu_mask = 1u64 << index;
                self.cpu_set.bitmask[self.mask_index].fetch_and(!cpu_mask, self.ordering);
                return Some((self.mask_index << 6) | index as usize);
            }
            self.mask_index += 1;
        }

        None
    }
}
