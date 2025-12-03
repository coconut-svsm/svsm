#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

use userlib::*;
extern crate alloc;
use alloc::boxed::Box;

declare_main!(main);

fn main() -> u32 {
    #[cfg(test)]
    {
        crate::userspace_test_main();
    }

    #[cfg(not(test))]
    {
        println!("COCONUT-SVSM init process starting");
        let b = Box::new([0u8; 256]);
        println!("Value: {:p}", b.as_ptr());
    }
    0
}

#[cfg(all(test, test_in_svsm))]
mod tests {
    use super::*;
    use alloc::vec;
    use core::ptr::{addr_of, addr_of_mut};

    static mut SOME_BSS_DATA: [u64; 128] = [0; 128];
    static mut SOME_DATA: [u64; 128] = [0x01; 128];
    static SOME_RO_DATA: [u64; 128] = [0xee; 128];

    fn check(arr: &[u64; 128], val: u64) {
        for v in arr.iter() {
            assert_eq!(*v, val, "Unexpected array value");
        }
    }

    fn write(arr: &mut [u64; 128], val: u64) {
        for v in arr.iter_mut() {
            *v = val;
        }
    }

    #[test]
    fn test_memory_check() {
        // SAFETY: Single-threaded process, so no data races. Safe to access global
        // mutable data.
        unsafe {
            write(&mut *addr_of_mut!(SOME_DATA), 0xcc);
            write(&mut *addr_of_mut!(SOME_BSS_DATA), 0xaa);
            check(&*addr_of!(SOME_DATA), 0xccu64);
            check(&*addr_of!(SOME_RO_DATA), 0xeeu64);
            check(&*addr_of!(SOME_BSS_DATA), 0xaa);
        }
    }

    #[test]
    fn test_alloc_behaviour() {
        let mut vec1 = vec![[0u8; 100]];
        let mut vec2 = vec![0u8; 1024];
        let mut vec3 = vec![[0u8; 1024]];
        let mut box1 = Box::new([0u8; 256]);

        let layout1 = layout_from_size(100).unwrap();
        assert_eq!(layout1.size(), 128);
        assert_eq!(layout1.align(), 128);

        let layout2 = layout_from_size(1024).unwrap();
        assert_eq!(layout2.size(), 1024);
        assert_eq!(layout2.align(), 1024);

        // SAFETY: The pointers are valid as they come from allocations.
        let layout3 = unsafe { layout_from_ptr(box1.as_mut_ptr()).unwrap() };
        assert_eq!(layout3.size(), 256);
        assert_eq!(layout3.align(), 256);

        // SAFETY: The pointers are valid as they come from allocations.
        let layout4 = unsafe { layout_from_ptr(vec1.as_mut_ptr() as *mut u8).unwrap() };
        assert_eq!(layout4.size(), 128);
        assert_eq!(layout4.align(), 128);

        // SAFETY: The pointers are valid as they come from allocations.
        let layout5 = unsafe { layout_from_ptr(vec2.as_mut_ptr()).unwrap() };
        assert_eq!(layout5.size(), 1024);
        assert_eq!(layout5.align(), 1024);

        // SAFETY: The pointers are valid as they come from allocations.
        let layout6 = unsafe { layout_from_ptr(vec3.as_mut_ptr() as *mut u8).unwrap() };
        assert_eq!(layout6.size(), 1024);
        assert_eq!(layout6.align(), 1024);
    }
}
