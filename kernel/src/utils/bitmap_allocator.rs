// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use core::fmt::Debug;

pub trait BitmapAllocator {
    const CAPACITY: usize;

    fn alloc(&mut self, entries: usize, align: usize) -> Option<usize>;
    fn free(&mut self, start: usize, entries: usize);

    fn set(&mut self, start: usize, entries: usize, value: bool);
    fn next_free(&self, start: usize) -> Option<usize>;
    fn get(&self, offset: usize) -> bool;
    fn empty(&self) -> bool;
    fn capacity(&self) -> usize;
    fn used(&self) -> usize;
    #[cfg(fuzzing)]
    fn max_align(&self) -> usize {
        (<Self as BitmapAllocator>::CAPACITY.ilog2() - 1) as usize
    }
}

pub type BitmapAllocator1024 = BitmapAllocatorTree<BitmapAllocator64>;

#[derive(Debug, Default, Copy, Clone)]
pub struct BitmapAllocator64 {
    bits: u64,
}

impl BitmapAllocator64 {
    pub const fn new_full() -> Self {
        Self { bits: u64::MAX }
    }

    pub const fn new_empty() -> Self {
        Self { bits: 0 }
    }

    #[cfg(fuzzing)]
    pub fn get_bits(&self) -> u64 {
        self.bits
    }
}

impl BitmapAllocator for BitmapAllocator64 {
    const CAPACITY: usize = u64::BITS as usize;

    fn alloc(&mut self, entries: usize, align: usize) -> Option<usize> {
        alloc_aligned(self, entries, align)
    }

    fn free(&mut self, start: usize, entries: usize) {
        self.set(start, entries, false);
    }

    fn set(&mut self, start: usize, entries: usize, value: bool) {
        assert!(entries > 0);
        assert!((start + entries) <= BitmapAllocator64::CAPACITY);
        // Create a mask for changing the bitmap
        let start_mask = !((1 << start) - 1);
        // Need to do some bit shifting to avoid overflow when top bit set
        let end_mask = (((1 << (start + entries - 1)) - 1) << 1) + 1;
        let mask = start_mask & end_mask;

        if value {
            self.bits |= mask;
        } else {
            self.bits &= !mask;
        }
    }

    fn next_free(&self, start: usize) -> Option<usize> {
        assert!(start < Self::CAPACITY);
        let mask: u64 = (1 << start) - 1;
        let idx = (self.bits | mask).trailing_ones() as usize;
        (idx < Self::CAPACITY).then_some(idx)
    }

    fn get(&self, offset: usize) -> bool {
        assert!(offset < BitmapAllocator64::CAPACITY);
        (self.bits & (1 << offset)) != 0
    }

    fn empty(&self) -> bool {
        self.bits == 0
    }

    fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    fn used(&self) -> usize {
        self.bits.count_ones() as usize
    }
}

#[derive(Debug, Default, Clone)]
pub struct BitmapAllocatorTree<T: BitmapAllocator + Debug> {
    bits: u16,
    child: [T; 16],
}

impl BitmapAllocatorTree<BitmapAllocator64> {
    pub const fn new_full() -> Self {
        Self {
            bits: u16::MAX,
            child: [BitmapAllocator64::new_full(); 16],
        }
    }

    pub const fn new_empty() -> Self {
        Self {
            bits: 0,
            child: [BitmapAllocator64::new_empty(); 16],
        }
    }

    #[cfg(fuzzing)]
    pub fn get_child(&self, index: usize) -> BitmapAllocator64 {
        self.child[index]
    }
}

impl<T: BitmapAllocator + Debug> BitmapAllocator for BitmapAllocatorTree<T> {
    const CAPACITY: usize = T::CAPACITY * 16;

    fn alloc(&mut self, entries: usize, align: usize) -> Option<usize> {
        alloc_aligned(self, entries, align)
    }

    fn free(&mut self, start: usize, entries: usize) {
        self.set(start, entries, false);
    }

    fn set(&mut self, start: usize, entries: usize, value: bool) {
        assert!((start + entries) <= Self::CAPACITY);
        let mut offset = start % T::CAPACITY;
        let mut remain = entries;
        for index in (start / T::CAPACITY)..16 {
            let child_size = if remain > (T::CAPACITY - offset) {
                T::CAPACITY - offset
            } else {
                remain
            };
            remain -= child_size;

            self.child[index].set(offset, child_size, value);
            if self.child[index].empty() {
                self.bits &= !(1 << index);
            } else {
                self.bits |= 1 << index;
            }
            if remain == 0 {
                break;
            }
            // Only the first loop iteration uses a non-zero offset
            offset = 0;
        }
    }

    fn next_free(&self, start: usize) -> Option<usize> {
        assert!(start < Self::CAPACITY);
        let mut offset = start % T::CAPACITY;
        for index in (start / T::CAPACITY)..16 {
            if let Some(next_offset) = self.child[index].next_free(offset) {
                return Some(next_offset + (index * T::CAPACITY));
            }
            // Only the first loop iteration uses a non-zero offset
            offset = 0;
        }
        None
    }

    fn get(&self, offset: usize) -> bool {
        assert!(offset < Self::CAPACITY);
        let index = offset / T::CAPACITY;
        self.child[index].get(offset % T::CAPACITY)
    }

    fn empty(&self) -> bool {
        self.bits == 0
    }

    fn capacity(&self) -> usize {
        Self::CAPACITY
    }

    fn used(&self) -> usize {
        self.child.iter().map(|c| c.used()).sum()
    }
}

fn alloc_aligned(ba: &mut impl BitmapAllocator, entries: usize, align: usize) -> Option<usize> {
    // Iterate through the bitmap checking on each alignment boundary
    // for a free range of the requested size
    if align >= (ba.capacity().ilog2() as usize) {
        return None;
    }
    let align_mask = (1 << align) - 1;
    let mut offset = 0;
    while (offset + entries) <= ba.capacity() {
        if let Some(offset_free) = ba.next_free(offset) {
            // If the next free offset does not match the current aligned
            // offset then move forward to the next aligned offset
            if offset_free != offset {
                offset = ((offset_free - 1) & !align_mask) + (1 << align);
                continue;
            }
            // The aligned offset is free. Keep checking the next bit until we
            // reach the requested size
            assert!((offset + entries) <= ba.capacity());
            let mut free_entries = 0;
            for size_check in offset..(offset + entries) {
                if !ba.get(size_check) {
                    free_entries += 1;
                } else {
                    break;
                }
            }
            if free_entries == entries {
                // Mark the range as in-use
                ba.set(offset, entries, true);
                return Some(offset);
            }
        }
        offset += 1 << align;
    }
    None
}

//
// Tests
//

#[cfg(test)]
mod tests {
    use super::{BitmapAllocator, BitmapAllocator64};

    use super::BitmapAllocatorTree;

    #[test]
    fn test_set_single() {
        let mut b = BitmapAllocator64 { bits: 0 };
        b.set(0, 1, true);
        assert_eq!(b.bits, 0x0000000000000001);
        b.set(8, 1, true);
        assert_eq!(b.bits, 0x0000000000000101);
        b.set(63, 1, true);
        assert_eq!(b.bits, 0x8000000000000101);
        assert_eq!(b.used(), 3);
    }

    #[test]
    fn test_clear_single() {
        let mut b = BitmapAllocator64 { bits: u64::MAX };
        b.set(0, 1, false);
        assert_eq!(b.bits, 0xfffffffffffffffe);
        b.set(8, 1, false);
        assert_eq!(b.bits, 0xfffffffffffffefe);
        b.set(63, 1, false);
        assert_eq!(b.bits, 0x7ffffffffffffefe);
        assert_eq!(b.used(), 64 - 3);
    }

    #[test]
    fn test_set_range() {
        let mut b = BitmapAllocator64 { bits: 0 };
        b.set(0, 9, true);
        assert_eq!(b.bits, 0x00000000000001ff);
        b.set(11, 4, true);
        assert_eq!(b.bits, 0x00000000000079ff);
        b.set(61, 3, true);
        assert_eq!(b.bits, 0xe0000000000079ff);
        assert_eq!(b.used(), 16);
    }

    #[test]
    fn test_clear_range() {
        let mut b = BitmapAllocator64 { bits: u64::MAX };
        b.set(0, 9, false);
        assert_eq!(b.bits, !0x00000000000001ff);
        b.set(11, 4, false);
        assert_eq!(b.bits, !0x00000000000079ff);
        b.set(61, 3, false);
        assert_eq!(b.bits, !0xe0000000000079ff);
        assert_eq!(b.used(), 64 - 16);
    }

    #[test]
    #[should_panic]
    fn test_exceed_range() {
        let mut b = BitmapAllocator64 { bits: 0 };
        b.set(0, 65, true);
    }

    #[test]
    #[should_panic]
    fn test_exceed_start() {
        let mut b = BitmapAllocator64 { bits: 0 };
        b.set(64, 1, true);
    }

    #[test]
    fn test_next_free() {
        let mut b = BitmapAllocator64 {
            bits: !0x8000000000000101,
        };
        assert_eq!(b.next_free(0), Some(0));
        assert_eq!(b.next_free(1), Some(8));
        assert_eq!(b.next_free(9), Some(63));
        b.set(63, 1, true);
        assert_eq!(b.next_free(9), None);
    }

    #[test]
    fn alloc_simple() {
        let mut b = BitmapAllocator64 { bits: 0 };
        assert_eq!(b.alloc(1, 0), Some(0));
        assert_eq!(b.alloc(1, 0), Some(1));
        assert_eq!(b.alloc(1, 0), Some(2));
    }

    #[test]
    fn alloc_aligned() {
        let mut b = BitmapAllocator64 { bits: 0 };
        // Alignment of 1 << 4 bits : 16 bit alignment
        assert_eq!(b.alloc(1, 4), Some(0));
        assert_eq!(b.alloc(1, 4), Some(16));
        assert_eq!(b.alloc(1, 4), Some(32));
    }

    #[test]
    fn alloc_large_aligned() {
        let mut b = BitmapAllocator64 { bits: 0 };
        // Alignment of 1 << 4 bits : 16 bit alignment
        assert_eq!(b.alloc(17, 4), Some(0));
        assert_eq!(b.alloc(1, 4), Some(32));
    }

    #[test]
    fn alloc_out_of_space() {
        let mut b = BitmapAllocator64 { bits: 0 };
        // Alignment of 1 << 4 bits : 16 bit alignment
        assert_eq!(b.alloc(50, 4), Some(0));
        assert_eq!(b.alloc(1, 4), None);
    }

    #[test]
    fn free_space() {
        let mut b = BitmapAllocator64 { bits: 0 };
        // Alignment of 1 << 4 bits : 16 bit alignment
        assert_eq!(b.alloc(50, 4), Some(0));
        assert_eq!(b.alloc(1, 4), None);
        b.free(0, 50);
        assert_eq!(b.alloc(1, 4), Some(0));
    }

    #[test]
    fn free_multiple() {
        let mut b = BitmapAllocator64 { bits: u64::MAX };
        b.free(0, 16);
        b.free(23, 16);
        b.free(41, 16);
        assert_eq!(b.alloc(16, 0), Some(0));
        assert_eq!(b.alloc(16, 0), Some(23));
        assert_eq!(b.alloc(16, 0), Some(41));
        assert_eq!(b.alloc(16, 0), None);
    }

    #[test]
    fn tree_set_all() {
        let mut b = BitmapAllocatorTree::<BitmapAllocator64>::new_full();
        b.set(0, 64 * 16, false);
        for i in 0..16 {
            assert_eq!(b.child[i].bits, 0);
        }
        assert_eq!(b.bits, 0);
        assert_eq!(b.used(), 0);
    }

    #[test]
    fn tree_clear_all() {
        let mut b = BitmapAllocatorTree::<BitmapAllocator64>::new_full();
        b.set(0, 64 * 16, true);
        for i in 0..16 {
            assert_eq!(b.child[i].bits, u64::MAX);
        }
        assert_eq!(b.bits, u16::MAX);
        assert_eq!(b.used(), 1024);
    }

    #[test]
    fn tree_set_some() {
        let mut b = BitmapAllocatorTree::<BitmapAllocator64>::new_full();

        // First child
        b.set(0, BitmapAllocatorTree::<BitmapAllocator64>::CAPACITY, false);
        b.set(11, 17, true);
        for i in 0..16 {
            if i == 0 {
                assert_eq!(b.child[i].bits, 0x000000000ffff800);
            } else {
                assert_eq!(b.child[i].bits, 0);
            }
        }
        assert_eq!(b.bits, 0x0001);
        assert_eq!(b.used(), 17);

        // Last child
        b.set(0, BitmapAllocatorTree::<BitmapAllocator64>::CAPACITY, false);
        b.set((15 * 64) + 11, 17, true);
        for i in 0..16 {
            if i == 15 {
                assert_eq!(b.child[i].bits, 0x000000000ffff800);
            } else {
                assert_eq!(b.child[i].bits, 0);
            }
        }
        assert_eq!(b.bits, 0x8000);
        assert_eq!(b.used(), 17);

        // Traverse child boundary
        b.set(0, BitmapAllocatorTree::<BitmapAllocator64>::CAPACITY, false);
        b.set(50, 28, true);
        for i in 0..16 {
            if i == 0 {
                assert_eq!(b.child[i].bits, 0xfffc000000000000);
            } else if i == 1 {
                assert_eq!(b.child[i].bits, 0x0000000000003fff);
            } else {
                assert_eq!(b.child[i].bits, 0);
            }
        }
        assert_eq!(b.bits, 0x0003);
        assert_eq!(b.used(), 28);
    }

    #[test]
    fn tree_alloc_simple() {
        let mut b = BitmapAllocatorTree::<BitmapAllocator64>::new_full();
        b.set(0, BitmapAllocatorTree::<BitmapAllocator64>::CAPACITY, false);
        for i in 0..256 {
            assert_eq!(b.alloc(1, 0), Some(i));
        }
        assert_eq!(b.used(), 256);
    }

    #[test]
    fn tree_alloc_empty_simple() {
        let mut b = BitmapAllocatorTree::<BitmapAllocator64>::new_empty();
        for i in 0..256 {
            assert_eq!(b.alloc(1, 0), Some(i));
        }
        assert_eq!(b.used(), 256);
    }

    #[test]
    fn tree_alloc_aligned() {
        let mut b = BitmapAllocatorTree::<BitmapAllocator64>::new_full();
        b.set(0, BitmapAllocatorTree::<BitmapAllocator64>::CAPACITY, false);
        // Alignment of 1 << 5 bits : 32 bit alignment
        assert_eq!(b.alloc(1, 5), Some(0));
        assert_eq!(b.alloc(1, 5), Some(32));
        assert_eq!(b.alloc(1, 5), Some(64));
        assert_eq!(b.alloc(1, 5), Some(96));
        assert_eq!(b.alloc(1, 5), Some(128));
        assert_eq!(b.alloc(1, 0), Some(1));
        assert_eq!(b.used(), 6);
    }

    #[test]
    fn tree_alloc_large_aligned() {
        let mut b = BitmapAllocatorTree::<BitmapAllocator64>::new_full();
        b.set(0, BitmapAllocatorTree::<BitmapAllocator64>::CAPACITY, false);
        // Alignment of 1 << 4 bits : 16 bit alignment
        assert_eq!(b.alloc(500, 4), Some(0));
        assert_eq!(b.alloc(400, 4), Some(512));
        assert_eq!(b.used(), 900);
    }

    #[test]
    fn tree_alloc_out_of_space() {
        let mut b = BitmapAllocatorTree::<BitmapAllocator64>::new_full();
        b.set(0, BitmapAllocatorTree::<BitmapAllocator64>::CAPACITY, false);
        // Alignment of 1 << 4 bits : 16 bit alignment
        assert_eq!(b.alloc(1000, 4), Some(0));
        assert_eq!(
            b.alloc(BitmapAllocatorTree::<BitmapAllocator64>::CAPACITY - 100, 4),
            None
        );
        assert_eq!(b.used(), 1000);
    }

    #[test]
    fn tree_free_space() {
        let mut b = BitmapAllocatorTree::<BitmapAllocator64>::new_full();
        b.set(0, BitmapAllocatorTree::<BitmapAllocator64>::CAPACITY, false);
        // Alignment of 1 << 4 bits : 16 bit alignment
        assert_eq!(
            b.alloc(BitmapAllocatorTree::<BitmapAllocator64>::CAPACITY - 10, 4),
            Some(0)
        );
        assert_eq!(b.alloc(1, 4), None);
        b.free(0, 50);
        assert_eq!(b.alloc(1, 4), Some(0));
        assert_eq!(b.used(), 965);
    }

    #[test]
    fn tree_free_multiple() {
        let mut b = BitmapAllocatorTree::<BitmapAllocator64>::new_full();
        b.set(0, BitmapAllocatorTree::<BitmapAllocator64>::CAPACITY, true);
        b.free(0, 16);
        b.free(765, 16);
        b.free(897, 16);
        assert_eq!(b.alloc(16, 0), Some(0));
        assert_eq!(b.alloc(16, 0), Some(765));
        assert_eq!(b.alloc(16, 0), Some(897));
        assert_eq!(b.alloc(16, 0), None);
        assert_eq!(b.used(), 1024);
    }
}
