// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};

// Re-export alignment utilities from paging crate
pub use paging::util::*;

/// # Safety
///
/// Caller should ensure [`core::ptr::write_bytes`] safety rules.
pub unsafe fn zero_mem_region(start: VirtAddr, end: VirtAddr) {
    if start.is_null() {
        panic!("Attempted to zero out a NULL pointer");
    }

    let count = end
        .checked_sub(start.as_usize())
        .expect("Invalid size calculation")
        .as_usize();

    // Zero region
    // SAFETY: the safety rules must be upheld by the caller.
    unsafe { start.as_mut_ptr::<u8>().write_bytes(0, count) }
}

/// Obtain bit for a given position
#[macro_export]
macro_rules! BIT {
    ($x: expr) => {
        (1 << ($x))
    };
}

/// Obtain bit mask for the given positions
#[macro_export]
macro_rules! BIT_MASK {
    ($e: expr, $s: expr) => {{
        assert!(
            $s <= 63 && $e <= 63 && $s <= $e,
            "Start bit position must be less than or equal to end bit position"
        );
        (((1u64 << ($e - $s + 1)) - 1) << $s)
    }};
}

#[cfg(test)]
mod tests {

    use crate::address::VirtAddr;
    use crate::utils::util::*;

    #[test]
    fn test_zero_mem_region() {
        let mut data: [u8; 10] = [1; 10];
        let start = VirtAddr::from(data.as_mut_ptr());
        let end = start + core::mem::size_of_val(&data);

        // SAFETY: start and end correctly point respectively to the start and
        // end of data.
        unsafe {
            zero_mem_region(start, end);
        }

        for byte in &data {
            assert_eq!(*byte, 0);
        }
    }
}
