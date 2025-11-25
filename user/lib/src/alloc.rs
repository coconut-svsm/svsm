// SPDX-License-Identifier: MIT

use crate::MMFlags;
use crate::mmap;
use coconut_alloc::AllocBlock;
use once_cell::race::OnceRef;

#[derive(Debug)]
pub enum AllocError {
    AlreadyInitialized,
    NotInitialized,
}

// FIXME
const HEAP_ADDR: usize = 0x100000;
const HEAP_SIZE: u64 = 64 * 1024;

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
