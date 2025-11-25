// SPDX-License-Identifier: MIT

use crate::{console_print, print, println};
use coconut_alloc::AllocBlock;
use core::ptr::{addr_of, addr_of_mut};
use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub enum AllocError {
    AlreadyInitialized,
    NotInitialized,
}

const UNINITIALIZED: usize = 0;
const INITIALIZING: usize = 1;
const INITIALIZED: usize = 2;

// One time initialization of a static mutable reference:
// https://doc.rust-lang.org/edition-guide/rust-2024/static-mut-references.html#no_std-one-time-initialization
static mut HEAP: AllocBlock = AllocBlock::new();
static STATE_INITIALIZED: AtomicUsize = AtomicUsize::new(UNINITIALIZED);

pub fn set_global_heap() -> Result<(), AllocError> {
    // Just a single initialization allowed
    if STATE_INITIALIZED
        .compare_exchange(
            UNINITIALIZED,
            INITIALIZING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_err()
    {
        println!("Heap initialization failed");
        return Err(AllocError::AlreadyInitialized);
    }

    // SAFETY: Only a single thread can reach this point
    unsafe {
        let heap = &mut *addr_of_mut!(HEAP);
        AllocBlock::initialize(heap);
    }
    STATE_INITIALIZED.store(INITIALIZED, Ordering::SeqCst);
    Ok(())
}

fn get_global_heap() -> Result<&'static AllocBlock, AllocError> {
    // fixme: this check can be removed.
    if STATE_INITIALIZED.load(Ordering::SeqCst) != INITIALIZED {
        println!("Heap not initialized");
        return Err(AllocError::NotInitialized);
    }
    // SAFETY: Heap is initialized at startup before any allocations occur.
    // STATE_INITIALIZED ensures single initialization.
    unsafe { Ok(&*addr_of!(HEAP)) }
}
