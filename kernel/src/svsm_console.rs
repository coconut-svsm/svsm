// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::cpu::percpu::current_ghcb;
use crate::io::IOPort;
use crate::sev::ghcb::GHCBIOSize;
use crate::sev::msr_protocol::request_termination_msr;

use core::arch::asm;

#[derive(Clone, Copy, Debug, Default)]
pub struct SVSMIOPort {}

impl SVSMIOPort {
    pub const fn new() -> Self {
        SVSMIOPort {}
    }
}

impl IOPort for SVSMIOPort {
    fn outb(&self, port: u16, value: u8) {
        let ret = current_ghcb().ioio_out(port, GHCBIOSize::Size8, value as u64);
        if ret.is_err() {
            request_termination_msr();
        }
    }

    fn inb(&self, port: u16) -> u8 {
        let ret = current_ghcb().ioio_in(port, GHCBIOSize::Size8);
        match ret {
            Ok(v) => (v & 0xff) as u8,
            Err(_e) => request_termination_msr(),
        }
    }

    fn outw(&self, port: u16, value: u16) {
        let ret = current_ghcb().ioio_out(port, GHCBIOSize::Size16, value as u64);
        if ret.is_err() {
            request_termination_msr();
        }
    }

    fn inw(&self, port: u16) -> u16 {
        let ret = current_ghcb().ioio_in(port, GHCBIOSize::Size16);
        match ret {
            Ok(v) => (v & 0xffff) as u16,
            Err(_e) => request_termination_msr(),
        }
    }

    fn outl(&self, port: u16, value: u32) {
        let ret = current_ghcb().ioio_out(port, GHCBIOSize::Size32, value as u64);
        if ret.is_err() {
            request_termination_msr();
        }
    }

    fn inl(&self, port: u16) -> u32 {
        let ret = current_ghcb().ioio_in(port, GHCBIOSize::Size32);
        match ret {
            Ok(v) => (v & 0xffffffff) as u32,
            Err(_e) => request_termination_msr(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NativeIOPort {}

impl NativeIOPort {
    pub const fn new() -> Self {
        NativeIOPort {}
    }
}

impl IOPort for NativeIOPort {
    fn outb(&self, port: u16, value: u8) {
        unsafe {
            asm!("out %al, %dx",
                 in("dx") port,
                 in("al") value,
                 options(att_syntax));
        }
    }

    fn inb(&self, port: u16) -> u8 {
        let mut ret: u8;
        unsafe {
            asm!("in %dx, %al",
                 in("dx") port,
                 out("al") ret,
                 options(att_syntax));
        }
        ret
    }

    fn outw(&self, port: u16, value: u16) {
        unsafe {
            asm!("out %ax, %dx",
                 in("dx") port,
                 in("ax") value,
                 options(att_syntax));
        }
    }

    fn inw(&self, port: u16) -> u16 {
        let mut ret: u16;
        unsafe {
            asm!("in %dx, %al",
                 in("dx") port,
                 out("ax") ret,
                 options(att_syntax));
        }
        ret
    }
}
