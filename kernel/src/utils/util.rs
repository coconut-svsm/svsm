// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
use crate::types::PAGE_SIZE;
use core::ops::{Add, BitAnd, Not, Sub};

use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
include!("util.verus.rs");

#[verus_spec(ret =>
    requires
        align_up_requires((addr, align)),
    ensures
        align_up_ens((addr, align), ret),
)]
pub fn align_up<T>(addr: T, align: T) -> T
where
    T: Add<Output = T> + Sub<Output = T> + BitAnd<Output = T> + Not<Output = T> + From<u8> + Copy,
{
    let mask: T = align - T::from(1u8);
    (addr + mask) & !mask
}

#[verus_spec(ret =>
    requires
        align_down_requires((addr, align)),
    ensures
        align_down_ens((addr, align), ret),
)]
pub fn align_down<T>(addr: T, align: T) -> T
where
    T: Sub<Output = T> + Not<Output = T> + BitAnd<Output = T> + From<u8> + Copy,
{
    addr & !(align - T::from(1u8))
}

#[verus_spec(ret =>
    requires
        is_aligned_requires((addr, align)),
    ensures
        is_aligned_ens((addr, align), ret)
)]
pub fn is_aligned<T>(addr: T, align: T) -> bool
where
    T: Sub<Output = T> + BitAnd<Output = T> + PartialEq + From<u8>,
{
    (addr & (align - T::from(1u8))) == T::from(0u8)
}

pub fn page_align_up(x: usize) -> usize {
    align_up(x, PAGE_SIZE)
}

pub fn page_offset(x: usize) -> usize {
    x & (PAGE_SIZE - 1)
}

pub fn overlap<T>(x1: T, x2: T, y1: T, y2: T) -> bool
where
    T: PartialOrd,
{
    x1 <= y2 && y1 <= x2
}

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

    use crate::utils::util::*;

    #[test]
    fn test_mem_utils() {
        // Align up
        assert_eq!(align_up(7, 4), 8);
        assert_eq!(align_up(15, 8), 16);
        assert_eq!(align_up(10, 2), 10);
        // Align down
        assert_eq!(align_down(7, 4), 4);
        assert_eq!(align_down(15, 8), 8);
        assert_eq!(align_down(10, 2), 10);
        // Page align up
        assert_eq!(page_align_up(4096), 4096);
        assert_eq!(page_align_up(4097), 8192);
        assert_eq!(page_align_up(0), 0);
        // Page offset
        assert_eq!(page_offset(4096), 0);
        assert_eq!(page_offset(4097), 1);
        assert_eq!(page_offset(0), 0);
        // Overlaps
        assert!(overlap(1, 5, 3, 6));
        assert!(overlap(0, 10, 5, 15));
        assert!(!overlap(1, 5, 6, 8));
    }

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
