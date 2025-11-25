use coconut_alloc::AllocBlock;
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicUsize, Ordering};

const MAX_ALLOC_SIZE: usize = 32 * 1024; // 32 KiB
const UNINITIALIZED: usize = 0;
const INITIALIZING: usize = 1;
const INITIALIZED: usize = 2;

static mut HEAP: AllocBlock = AllocBlock::new();
static STATE_INITIALIZED: AtomicUsize = AtomicUsize::new(UNINITIALIZED);

pub fn set_global_heap() {
    // Just a single initialization allowed
    if STATE_INITIALIZED
        .compare_exchange(
            UNINITIALIZED,
            INITIALIZING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_ok()
    {
        // SAFETY: Only a single thread can reach this point
        unsafe {
            let heap = &mut *addr_of_mut!(HEAP);
            AllocBlock::initialize(heap);
        }
        STATE_INITIALIZED.store(INITIALIZED, Ordering::SeqCst);
    } else {
        panic!("Already initialized, or concurrent initialization detected");
    }
}

fn get_global_heap() -> &'static AllocBlock {
    // fixme: this check can be removed.
    if STATE_INITIALIZED.load(Ordering::SeqCst) != INITIALIZED {
        panic!("Heap not initialized");
    }
    // SAFETY: Heap is initialized at startup before any allocations occur.
    // STATE_INITIALIZED ensures single initialization.
    unsafe { &*addr_of!(HEAP) }
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

        let heap = get_global_heap();

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
        let heap = get_global_heap();

        let base = heap as *const AllocBlock as *const u8;
        // SAFETY: ptr must have been allocated from this heap
        let off = unsafe { ptr.offset_from(base) as usize };

        heap.free(off);
    }
}

#[cfg(all(not(test), target_os = "none"))]
#[global_allocator]
static GLOBAL_ALLOC: SvsmUserAllocator = SvsmUserAllocator;
