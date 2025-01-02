// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use svsm::utils::bitmap_allocator::{BitmapAllocator, BitmapAllocator1024, BitmapAllocator64};

#[derive(Arbitrary, Debug)]
enum BmaAction {
    Alloc(usize, usize),
    Free(usize, usize),
    Set(usize, usize, bool),
    NextFree(usize),
}

pub trait TestBitmapAllocator: BitmapAllocator {
    fn prune_alloc_params(&self, entries: usize, align: usize) -> (usize, usize) {
        let align_p = align % (self.max_align() + 1);
        let entries_limit = self.capacity() - (1 << align_p);
        let entries_p = (entries % entries_limit) + 1;
        (entries_p, align_p)
    }

    fn prune_set_params(&self, start: usize, entries: usize) -> (usize, usize) {
        let start_p = start % self.capacity();
        let entries_limit = self.capacity() - start_p;
        let entries_p = (entries % entries_limit) + 1;
        (start_p, entries_p)
    }

    fn test_alloc(&self, bma_before: &Self, entries: usize, align: usize, offset: Option<usize>) {
        match offset {
            Some(offset) => {
                assert_eq!(offset % (1 << align), 0);
                self.test_set(bma_before, offset, entries, true);
            }
            None => {
                if align <= self.max_align() {
                    for i in (0..=(self.capacity() - entries)).step_by(1 << align) {
                        let mut flag = false;
                        for j in 0..entries {
                            if self.get(i + j) {
                                flag = true;
                                break;
                            }
                        }
                        assert!(flag);
                    }
                }
            }
        }
    }
    fn test_set(&self, bma: &Self, start: usize, entries: usize, val: bool);
    fn test_nextfree(&self, start: usize, res: Option<usize>);
}

impl TestBitmapAllocator for BitmapAllocator64 {
    fn test_set(&self, bma64_before: &Self, start: usize, entries: usize, val: bool) {
        let start_mask = !((1 << start) - 1);
        let end_mask = (((1 << (start + entries - 1)) - 1) << 1) + 1;
        let mask = start_mask & end_mask;
        if val {
            assert_eq!(bma64_before.get_bits() | mask, self.get_bits());
        } else {
            assert_eq!(bma64_before.get_bits() & !mask, self.get_bits());
        }
    }

    fn test_nextfree(&self, start: usize, res: Option<usize>) {
        match res {
            Some(res) => {
                assert!(res >= start);
                assert!(!self.get(res));
                if res > start {
                    let mask: u64 = ((1 << (res - start)) - 1) << start;
                    assert_eq!(self.get_bits() & mask, mask);
                }
            }
            None => {
                let mask: u64 = (1 << start) - 1;
                assert_eq!(
                    (self.get_bits() | mask).trailing_ones(),
                    self.capacity() as u32
                );
            }
        }
    }
}

impl TestBitmapAllocator for BitmapAllocator1024 {
    fn test_set(&self, bma1024_before: &Self, start: usize, entries: usize, val: bool) {
        let capacity = self.get_child(0).capacity();
        let first = start / capacity;
        let last = (start + entries - 1) / capacity;
        let mut off = start % capacity;
        let mut remain = entries;
        let mut size;
        for i in 0..16 {
            let bma64 = self.get_child(i);
            let bma64_before = bma1024_before.get_child(i);
            if i >= first && i <= last {
                size = if (off + remain) > capacity {
                    capacity - off
                } else {
                    remain
                };
                bma64.test_set(&bma64_before, off, size, val);
                remain -= size;
                if remain == 0 {
                    continue;
                }
                off = 0;
            } else {
                assert_eq!(bma64.get_bits(), bma64_before.get_bits());
            }
        }
    }

    fn test_nextfree(&self, start: usize, res: Option<usize>) {
        let capacity = self.get_child(0).capacity();
        match res {
            Some(res) => {
                let first = start / capacity;
                let last = res / capacity;
                let mut off_start = start % capacity;
                let off_last = res % capacity;
                for i in first..last {
                    assert_eq!(self.get_child(i).next_free(off_start), None);
                    off_start = 0;
                }
                let bma64_last = self.get_child(last);
                assert!(!bma64_last.get(off_last));
                assert_eq!(bma64_last.next_free(off_start), Some(off_last));
            }
            None => {
                let first = start / capacity;
                let mut off_start = start % capacity;
                for i in first..16 {
                    assert_eq!(self.get_child(i).next_free(off_start), None);
                    off_start = 0;
                }
            }
        }
    }
}

fuzz_target!(|actions: Vec<BmaAction>| {
    let mut bma64 = BitmapAllocator64::new_full();
    let mut bma1024 = BitmapAllocator1024::new_full();
    for action in actions.iter() {
        let bma64_before = bma64;
        let bma1024_before = bma1024.clone();
        match action {
            BmaAction::Alloc(entries, align) => {
                let (entries_p, align_p) = bma64.prune_alloc_params(*entries, *align);
                let offset = bma64.alloc(entries_p, align_p);
                bma64.test_alloc(&bma64_before, entries_p, align_p, offset);

                let (entries_p, align_p) = bma1024.prune_alloc_params(*entries, *align);
                let offset = bma1024.alloc(entries_p, align_p);
                bma1024.test_alloc(&bma1024_before, entries_p, align_p, offset);
            }
            BmaAction::Free(start, entries) => {
                let (start_p, entries_p) = bma64.prune_set_params(*start, *entries);
                bma64.free(start_p, entries_p);
                bma64.test_set(&bma64_before, start_p, entries_p, false);

                let (start_p, entries_p) = bma1024.prune_set_params(*start, *entries);
                bma1024.free(start_p, entries_p);
                bma1024.test_set(&bma1024_before, start_p, entries_p, false);
            }
            BmaAction::Set(start, entries, value) => {
                let (start_p, entries_p) = bma64.prune_set_params(*start, *entries);
                bma64.set(start_p, entries_p, *value);
                bma64.test_set(&bma64_before, start_p, entries_p, *value);

                let (start_p, entries_p) = bma1024.prune_set_params(*start, *entries);
                bma1024.set(start_p, entries_p, *value);
                bma1024.test_set(&bma1024_before, start_p, entries_p, *value);
            }
            BmaAction::NextFree(start) => {
                let res = bma64.next_free(start % bma64.capacity());
                bma64.test_nextfree(start % bma64.capacity(), res);

                let res = bma1024.next_free(start % bma1024.capacity());
                bma1024.test_nextfree(start % bma1024.capacity(), res);
            }
        }
    }
});
