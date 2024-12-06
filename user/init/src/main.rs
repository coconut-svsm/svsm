#![no_std]
#![no_main]

use userlib::*;

use core::ptr::{addr_of, addr_of_mut};

static mut SOME_BSS_DATA: [u64; 128] = [0; 128];
static mut SOME_DATA: [u64; 128] = [0x01; 128];
static SOME_RO_DATA: [u64; 128] = [0xee; 128];

fn check(arr: &[u64; 128], val: u64) {
    for v in arr.iter() {
        if *v != val {
            panic!("Unexpected array value");
        }
    }
}

fn write(arr: &mut [u64; 128], val: u64) {
    for v in arr.iter_mut() {
        *v = val;
    }
}

declare_main!(main);

fn main() -> u32 {
    println!("COCONUT-SVSM init process starting");

    // SAFETY: Single-threaded process, so no data races. Safe to access global
    // mutable data.
    unsafe {
        write(&mut *addr_of_mut!(SOME_DATA), 0xcc);
        write(&mut *addr_of_mut!(SOME_BSS_DATA), 0xaa);
        check(&*addr_of!(SOME_DATA), 0xccu64);
        check(&*addr_of!(SOME_RO_DATA), 0xeeu64);
        check(&*addr_of!(SOME_BSS_DATA), 0xaa);
    }
    0
}
