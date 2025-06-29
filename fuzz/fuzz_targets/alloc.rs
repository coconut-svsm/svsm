// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com>

#![no_main]

use arbitrary::Arbitrary;
use core::alloc::{GlobalAlloc, Layout, LayoutError};
use core::num::NonZeroUsize;
use libfuzzer_sys::fuzz_target;
use svsm::mm::alloc::{SvsmAllocator, TestRootMem};

const MIN_ROOT_MEM_SIZE: usize = 0x8000;
const MAX_ROOT_MEM_SIZE: usize = 0x100000;

#[inline]
fn adjust_mem_size(size: usize) -> usize {
    MIN_ROOT_MEM_SIZE + (size % (MAX_ROOT_MEM_SIZE - MIN_ROOT_MEM_SIZE + 1))
}

#[derive(Arbitrary, Debug)]
struct FuzzLayout {
    size: usize,
    align: usize,
}

impl TryFrom<FuzzLayout> for Layout {
    type Error = LayoutError;

    fn try_from(ly: FuzzLayout) -> Result<Self, Self::Error> {
        Self::from_size_align(ly.size, ly.align)
    }
}

/// A wrapper around SvsmAllocator that marks memory as initialized or
/// uninitialized on allocation and deallocation respectively.
struct PoisonAllocator {
    heap: SvsmAllocator,
}

impl PoisonAllocator {
    const POISON_BYTE: u8 = 0xf7;
    const WRITE_BYTE: u8 = 0x8;

    fn new() -> Self {
        Self {
            heap: SvsmAllocator::new(),
        }
    }

    /// # Safety
    ///
    /// The caller must provide valid memory given by the allocator.
    unsafe fn unpoison_mem(&self, ptr: *mut u8, size: usize) {
        // SAFETY: the caller must guarantee `ptr` is valid
        unsafe {
            ptr.write_bytes(Self::WRITE_BYTE, size);
        }
    }

    /// # Safety
    ///
    /// The caller must provide valid memory given by the allocator.
    unsafe fn poison_mem(&self, ptr: *mut u8, size: usize) {
        // SAFETY: the caller must guarantee `ptr` is valid
        unsafe {
            ptr.write_bytes(Self::POISON_BYTE, size);
        }
    }

    /// # Safety
    ///
    /// The caller must provide valid memory given by the allocator.
    unsafe fn check_mem(&self, ptr: *mut u8, size: usize) {
        for i in 0..size {
            // SAFETY: the caller must guarantee ptr is valid for `size` elements
            assert_eq!(unsafe { ptr.add(i).read_volatile() }, Self::WRITE_BYTE);
        }
    }

    fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: this cannot cause UB because SvsmAllocator properly handles
        // zero-sized allocations.
        let ptr = unsafe { self.heap.alloc(layout) };
        if !ptr.is_null() {
            // SAFETY: `ptr` comes from the allocator above
            unsafe { self.unpoison_mem(ptr, layout.size()) };
        }
        ptr
    }

    /// # Safety
    ///
    /// The caller must provide valid memory given by the allocator.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller must guarantee `ptr` is valid and the layout
        // is correct for the allocation
        unsafe {
            self.check_mem(ptr, layout.size());
            self.poison_mem(ptr, layout.size());
            self.heap.dealloc(ptr, layout);
        }
    }

    /// # Safety
    ///
    /// The caller must provide valid memory given by the allocator.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_layout: Layout) -> *mut u8 {
        // SAFETY: The caller must provide valid memory and its corresponding
        // layout
        unsafe {
            self.check_mem(ptr, layout.size());
            self.poison_mem(ptr, layout.size());
            let ptr = self.heap.realloc(ptr, layout, new_layout.size());
            if !ptr.is_null() {
                self.unpoison_mem(ptr, new_layout.size());
            }
            ptr
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Action {
    Alloc(FuzzLayout),
    Free(usize),
    Realloc(usize, NonZeroUsize),
    Read(usize),
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    root_mem_size: usize,
    actions: Vec<Action>,
}

fuzz_target!(|inp: FuzzInput| {
    let _mem = TestRootMem::setup(adjust_mem_size(inp.root_mem_size));
    let heap = PoisonAllocator::new();
    let mut ptrs = Vec::new();

    for action in inp.actions.into_iter() {
        match action {
            Action::Alloc(layout) => {
                let Ok(layout) = Layout::try_from(layout) else {
                    continue;
                };
                let ptr = heap.alloc(layout);
                if !ptr.is_null() {
                    ptrs.push((ptr, layout));
                }
            }
            Action::Free(idx) => {
                if let Some(idx) = idx.checked_rem(ptrs.len()) {
                    let (ptr, layout) = ptrs.swap_remove(idx);
                    // SAFETY: `ptr` and `layout` come from the allocator,
                    // since we stored them earlier into `ptrs`
                    unsafe { heap.dealloc(ptr, layout) };
                }
            }
            Action::Read(idx) => {
                if let Some(idx) = idx.checked_rem(ptrs.len()) {
                    let (ptr, layout) = ptrs[idx];
                    // SAFETY: `ptr` and `layout` come from the allocator,
                    // since we stored them earlier into `ptrs`
                    unsafe { heap.check_mem(ptr, layout.size()) };
                };
            }
            Action::Realloc(idx, new_size) => {
                let Some(idx) = idx.checked_rem(ptrs.len()) else {
                    continue;
                };

                // Try to get the new layout. Alignment must be the same.
                let new_size = new_size.get();
                let (ptr, layout) = ptrs.swap_remove(idx);
                let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
                    ptrs.push((ptr, layout));
                    continue;
                };

                // SAFETY: `ptr` and `layout` come from the allocator,
                // since we stored them earlier into `ptrs`
                let ptr = unsafe { heap.realloc(ptr, layout, new_layout) };
                if !ptr.is_null() {
                    ptrs.push((ptr, new_layout));
                }
            }
        }
    }

    for (ptr, layout) in ptrs.into_iter() {
        // SAFETY: `ptr` and `layout` come from the allocator, since we
        // stored them earlier into `ptrs`
        unsafe { heap.dealloc(ptr, layout) };
    }
});
