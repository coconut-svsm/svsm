// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use core::arch::asm;
use core::fmt::Debug;

pub trait IOPort: Sync + Debug {
    fn outb(&self, port: u16, value: u8) {
        // SAFETY: Inline assembly to write an ioport, which does not change
        // any state related to memory safety.
        unsafe { asm!("outb %al, %dx", in("al") value, in("dx") port, options(att_syntax)) }
    }

    fn inb(&self, port: u16) -> u8 {
        // SAFETY: Inline assembly to read an ioport, which does not change
        // any state related to memory safety.
        unsafe {
            let ret: u8;
            asm!("inb %dx, %al", in("dx") port, out("al") ret, options(att_syntax));
            ret
        }
    }

    fn outw(&self, port: u16, value: u16) {
        // SAFETY: Inline assembly to write an ioport, which does not change
        // any state related to memory safety.
        unsafe { asm!("outw %ax, %dx", in("ax") value, in("dx") port, options(att_syntax)) }
    }

    fn inw(&self, port: u16) -> u16 {
        // SAFETY: Inline assembly to read an ioport, which does not change
        // any state related to memory safety.
        unsafe {
            let ret: u16;
            asm!("inw %dx, %ax", in("dx") port, out("ax") ret, options(att_syntax));
            ret
        }
    }

    fn outl(&self, port: u16, value: u32) {
        // SAFETY: Inline assembly to write an ioport, which does not change
        // any state related to memory safety.
        unsafe { asm!("outl %eax, %dx", in("eax") value, in("dx") port, options(att_syntax)) }
    }

    fn inl(&self, port: u16) -> u32 {
        // SAFETY: Inline assembly to read an ioport, which does not change
        // any state related to memory safety.
        unsafe {
            let ret: u32;
            asm!("inl %dx, %eax", in("dx") port, out("eax") ret, options(att_syntax));
            ret
        }
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct DefaultIOPort {}

impl IOPort for DefaultIOPort {}

pub static DEFAULT_IO_DRIVER: DefaultIOPort = DefaultIOPort {};
