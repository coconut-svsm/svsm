// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::types::PAGE_SHIFT;
use crate::utils::{align_down, align_up};
use core::cmp::max;
use intrusive_collections::rbtree::{Link, RBTree};
use intrusive_collections::{intrusive_adapter, KeyAdapter};

extern crate alloc;
use alloc::boxed::Box;

struct Range<T> {
    link: Link,
    start: usize,
    end: usize,
    data: T,
}

impl<T> Range<T> {
    const fn new(start: usize, end: usize, data: T) -> Self {
        Self {
            link: Link::new(),
            start,
            end,
            data,
        }
    }

    fn get(&self) -> &T {
        &self.data
    }
}

intrusive_adapter!(RangeAdapater<T> = Box<Range<T>>: Range::<T> { link: Link });

impl<'a, T> KeyAdapter<'a> for RangeAdapater<T> {
    type Key = usize;
    fn get_key(&self, node: &'a Range<T>) -> usize {
        node.start
    }
}

pub struct AddressAllocator<T> {
    tree: RBTree<RangeAdapater<T>>,
    pfn_low: usize,
    pfn_high: usize,
}

impl<T> AddressAllocator<T> {
    pub fn new(low: usize, high: usize) -> Self {
        Self {
            tree: RBTree::new(RangeAdapater::new()),
            pfn_low: low >> PAGE_SHIFT,
            pfn_high: high >> PAGE_SHIFT,
        }
    }

    pub fn alloc_aligned(&mut self, size: usize, align: usize, data: T) -> Option<usize> {
        assert!(align.is_power_of_two());

        let size = size.checked_next_power_of_two().unwrap_or(0) >> PAGE_SHIFT;
        let align = align >> PAGE_SHIFT;
        let mut start = align_up(self.pfn_low, align);
        let mut end = start;

        if size == 0 {
            return None;
        }

        let mut cursor = self.tree.front_mut();
        while !cursor.is_null() {
            let node = cursor.get().unwrap();
            end = node.start;
            if end > start && end - start >= size {
                break;
            }
            start = max(start, align_up(node.end, align));
            cursor.move_next();
        }

        if cursor.is_null() {
            end = align_down(self.pfn_high, align);
        }

        if end > start && end - start >= size {
            cursor.insert_before(Box::new(Range::<T>::new(start, start + size, data)));
            Some(start << PAGE_SHIFT)
        } else {
            None
        }
    }

    pub fn alloc(&mut self, size: usize, data: T) -> Option<usize> {
        let align = size.next_power_of_two();

        self.alloc_aligned(size, align, data)
    }

    pub fn free(&mut self, start: usize) {
        let start = start >> PAGE_SHIFT;
        let mut cursor = self.tree.find_mut(&start);

        if !cursor.is_null() {
            cursor.remove();
        }
    }

    pub fn get(&self, start: usize) -> Option<&T> {
        let start = start >> PAGE_SHIFT;
        let cursor = self.tree.find(&start);

        cursor.get().map(|range| range.get())
    }
}

#[cfg(test)]
mod tests {
    use super::AddressAllocator;

    /// 1 MiB
    const MB: usize = 1024 * 1024;
    /// 1 GiB
    const GB: usize = 1024 * MB;
    /// 1 GiB
    const RANGE_START: usize = 1 * GB;
    /// 2 GiB
    const RANGE_END: usize = 2 * GB;

    const MAGIC: u64 = 0xf00b05;

    fn alloc_size<T>(allocator: &mut AddressAllocator<T>, size: usize, data: T) -> usize {
        let align_mask = size.next_power_of_two() - 1;
        let addr = allocator.alloc(size, data).unwrap();

        // Allocated range within allocator range?
        assert!(addr >= RANGE_START && addr <= RANGE_END - size);

        // Allocated address naturally aligned?
        assert!(addr & align_mask == 0);

        addr
    }

    #[test]
    fn alloc() {
        let mut allocator = AddressAllocator::<u64>::new(RANGE_START, RANGE_END);

        alloc_size::<u64>(&mut allocator, 512 * MB, 0);
    }

    #[test]
    fn alloc_full() {
        let mut allocator = AddressAllocator::<u64>::new(RANGE_START, RANGE_END);

        alloc_size::<u64>(&mut allocator, 512 * MB, 0);
        alloc_size::<u64>(&mut allocator, 512 * MB, 0);
        assert!(allocator.alloc(512 * MB, 0).is_none());
    }

    #[test]
    fn alloc_all() {
        let mut allocator = AddressAllocator::<u64>::new(RANGE_START, RANGE_END);

        alloc_size::<u64>(&mut allocator, RANGE_END - RANGE_START, 0);
    }

    #[test]
    fn over_alloc() {
        let mut allocator = AddressAllocator::<u64>::new(RANGE_START, RANGE_END);

        assert!(allocator.alloc(RANGE_END - RANGE_START + 1, 0).is_none());
    }

    #[test]
    fn get_data() {
        let mut allocator = AddressAllocator::<u64>::new(RANGE_START, RANGE_END);

        alloc_size::<u64>(&mut allocator, 23 * MB, 0);

        let addr = alloc_size::<u64>(&mut allocator, 512 * MB, MAGIC);

        let data = allocator.get(addr).unwrap();
        assert!(*data == MAGIC);
    }

    #[test]
    fn free() {
        let mut allocator = AddressAllocator::<u64>::new(RANGE_START, RANGE_END);

        alloc_size::<u64>(&mut allocator, 23 * MB, 0);

        let addr = alloc_size::<u64>(&mut allocator, 512 * MB, MAGIC);

        let data = allocator.get(addr).unwrap();
        assert!(*data == MAGIC);

        allocator.free(addr);
        assert!(allocator.get(addr).is_none());
    }
}
