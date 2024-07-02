// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::types::Bytes;
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

    fn ioio_out(&self, port: u16, size: Bytes, data: u64) {
        match size {
            Bytes::One => self.outb(port, data as u8),
            Bytes::Two => self.outw(port, data as u16),
            Bytes::Four => self.outl(port, data as u32),
            _ => panic!("Invalid output IO port size"),
        }
    }

    fn ioio_in(&self, port: u16, size: Bytes) -> u64 {
        match size {
            Bytes::One => self.inb(port) as u64,
            Bytes::Two => self.inw(port) as u64,
            Bytes::Four => self.inl(port) as u64,
            _ => panic!("Invalid input IO port size"),
        }
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct DefaultIOPort {}

impl IOPort for DefaultIOPort {}

pub static DEFAULT_IO_DRIVER: DefaultIOPort = DefaultIOPort {};
