// SPDX-License-Identifier: MIT OR Apache-2.0
//

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
compile_error!(
    "This crate is only meant to be used for testing purposes. \
    It should not be built outside of a test context."
);

use userlib::*;

#[cfg(test)]
declare_main!(main);

#[cfg(test)]
fn main() -> u32 {
    crate::usermodule_tests_in_svsm();
    0
}

#[cfg(test)]
mod tests {
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
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_memory_check() {
        // SAFETY: Single-threaded process, so no data races. Safe to access global
        // mutable data.
        unsafe {
            write(&mut *(&raw mut SOME_DATA), 0xcc);
            write(&mut *(&raw mut SOME_BSS_DATA), 0xaa);
            check(&*(&raw const SOME_DATA), 0xccu64);
            check(&*(&raw const SOME_RO_DATA), 0xeeu64);
            check(&*(&raw const SOME_BSS_DATA), 0xaa);
        }
    }
}
