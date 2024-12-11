// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::error::SvsmError;
use core::arch::asm;
use core::fmt::Debug;

pub trait IOPort: Sync + Debug {
    fn outb(&self, port: u16, value: u8) {
        unsafe { asm!("outb %al, %dx", in("al") value, in("dx") port, options(att_syntax)) }
    }

    fn inb(&self, port: u16) -> u8 {
        unsafe {
            let ret: u8;
            asm!("inb %dx, %al", in("dx") port, out("al") ret, options(att_syntax));
            ret
        }
    }

    fn outw(&self, port: u16, value: u16) {
        unsafe { asm!("outw %ax, %dx", in("ax") value, in("dx") port, options(att_syntax)) }
    }

    fn inw(&self, port: u16) -> u16 {
        unsafe {
            let ret: u16;
            asm!("inw %dx, %ax", in("dx") port, out("ax") ret, options(att_syntax));
            ret
        }
    }

    fn outl(&self, port: u16, value: u32) {
        unsafe { asm!("outl %eax, %dx", in("eax") value, in("dx") port, options(att_syntax)) }
    }

    fn inl(&self, port: u16) -> u32 {
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

/// Generic Read trait to be implemented over any transport channel when reading multiple bytes.
pub trait Read {
    type Err: Into<SvsmError>;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err>;
}

/// Generic Write trait to be implemented over any transport channel when writing multiple bytes.
pub trait Write {
    type Err: Into<SvsmError>;

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err>;
}
