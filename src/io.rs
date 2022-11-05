// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use core::arch::asm;

pub trait IOPort {
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
}

pub struct DefaultIOPort {}

impl IOPort for DefaultIOPort {}

pub static DEFAULT_IO_DRIVER: DefaultIOPort = DefaultIOPort {};
