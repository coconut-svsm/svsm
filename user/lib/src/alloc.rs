// SPDX-License-Identifier: MIT

use crate::MMFlags;
use crate::mmap;
use coconut_alloc::AllocBlock;
use once_cell::race::OnceRef;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

#[derive(Debug)]
pub enum AllocError {
    AlreadyInitialized,
    NotInitialized,
    Layout,
}

// FIXME
const HEAP_ADDR: usize = 0x100000;
const HEAP_SIZE: u64 = 64 * 1024;
const MAX_ALLOC_SIZE: usize = 32 * 1024;

static HEAP: OnceRef<'static, AllocBlock> = OnceRef::new();

/// HEAP initialization happens before main is called. The process is single-threaded
/// when initializing the HEAP. Successive calls to this function will return an error.
pub fn set_global_heap() -> Result<(), AllocError> {
    if HEAP.get().is_some() {
        return Err(AllocError::AlreadyInitialized);
    }

    let flags = MMFlags::MAP_READ | MMFlags::MAP_WRITE | MMFlags::MAP_PRIVATE;

    // SAFETY: This is called only once at init time.
    // The address return by mmap should be aligned at 64KB as the HEAP_SIZE is.
    unsafe {
        let addr =
            mmap(None, HEAP_ADDR, 0, HEAP_SIZE, flags).map_err(|_| AllocError::NotInitialized)?;

        let block = addr as *mut AllocBlock;

        (*block).initialize();

        HEAP.set(&*block)
            .map_err(|_| AllocError::AlreadyInitialized)?;
    }
    Ok(())
}

fn get_global_heap() -> Result<&'static AllocBlock, AllocError> {
    HEAP.get().ok_or(AllocError::NotInitialized)
}

struct SvsmUserAllocator;

// SAFETY: AllockBlock is lockless for allocations up to 32KB.
// HEAP is write-once and only read via immutable references after initialization.
// AllocBlock uses atomic operations internally to handle concurrent alloc/free safely.
unsafe impl GlobalAlloc for SvsmUserAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 || layout.size() > MAX_ALLOC_SIZE {
            return ptr::null_mut();
        }

        let Ok(heap) = get_global_heap() else {
            panic!("Global heap not initialized");
        };

        match heap.alloc(layout.size()) {
            Ok(off) => {
                let base = heap as *const AllocBlock as *const u8;
                // SAFETY: Atomic allocation just performed
                // The offset is valid
                unsafe { base.add(off) as *mut u8 }
            }
            Err(_) => ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let Ok(heap) = get_global_heap() else {
            panic!("Global heap not initialized");
        };

        let base = heap as *const AllocBlock as *const u8;
        // SAFETY: ptr must have been allocated from this heap
        let off = unsafe { ptr.offset_from(base) as usize };

        heap.free(off);
    }
}

#[global_allocator]
static GLOBAL_ALLOC: SvsmUserAllocator = SvsmUserAllocator;

/// Build a Layout suitable for requests to the coconut allocator.
pub fn layout_from_size(size: usize) -> Result<Layout, AllocError> {
    if size == 0 || size > MAX_ALLOC_SIZE {
        return Err(AllocError::Layout);
    }
    let next = size.next_power_of_two();

    Layout::from_size_align(next, next).map_err(|_| AllocError::Layout)
}

/// Try to reconstruct the Layout for a pointer previously returned by
/// an allocation.
/// # Safety
/// The pointer must have been allocated from the global heap.
pub unsafe fn layout_from_ptr(ptr: *mut u8) -> Option<Layout> {
    let Ok(heap) = get_global_heap() else {
        return None;
    };
    let base = heap as *const AllocBlock as *const u8;

    // SAFETY: ptr must have been allocated from this heap
    let off = unsafe { ptr.offset_from(base) };

    if off < 0 {
        // Should I check upper bound too? Importing BLOCK_SIZE from coconut_alloc
        return None;
    }

    heap.layout_from_offset(off as usize)
}
