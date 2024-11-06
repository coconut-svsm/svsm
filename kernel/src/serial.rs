// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::io::{IOPort, DEFAULT_IO_DRIVER};
use crate::{error::SvsmError, io};
use core::fmt::Debug;

pub const SERIAL_PORT: u16 = 0x3f8;
const BAUD: u32 = 9600;
const DLAB: u8 = 0x80;

pub const TXR: u16 = 0; // Transmit register
pub const _RXR: u16 = 0; // Receive register
pub const IER: u16 = 1; // Interrupt enable
pub const _IIR: u16 = 2; // Interrupt ID
pub const FCR: u16 = 2; // FIFO Control
pub const LCR: u16 = 3; // Line Control
pub const MCR: u16 = 4; // Modem Control
pub const LSR: u16 = 5; // Line Status
pub const _MSR: u16 = 6; // Modem Status
pub const DLL: u16 = 0; // Divisor Latch Low
pub const DLH: u16 = 1; // Divisor Latch High

pub const RCVRDY: u8 = 0x01;
pub const XMTRDY: u8 = 0x20;

pub trait Terminal: Sync + Debug {
    fn put_byte(&self, _ch: u8) {}
    fn get_byte(&self) -> u8 {
        0
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SerialPort<'a> {
    driver: &'a dyn IOPort,
    port: u16,
}

impl<'a> SerialPort<'a> {
    pub const fn new(driver: &'a dyn IOPort, p: u16) -> Self {
        SerialPort { driver, port: p }
    }

    pub fn init(&self) {
        let divisor: u32 = 115200 / BAUD;

        self.outb(LCR, 0x3); // 8n1
        self.outb(IER, 0x0); // No Interrupt
        self.outb(FCR, 0x0); // No FIFO
        self.outb(MCR, 0x3); // DTR + RTS

        let c = self.inb(LCR);
        self.outb(LCR, c | DLAB);
        self.outb(DLL, (divisor & 0xff) as u8);
        self.outb(DLH, ((divisor >> 8) & 0xff) as u8);
        self.outb(LCR, c & !DLAB);
    }

    #[inline]
    fn inb(&self, port: u16) -> u8 {
        self.driver.inb(self.port + port)
    }

    #[inline]
    fn outb(&self, port: u16, val: u8) {
        self.driver.outb(self.port + port, val);
    }
}

impl Terminal for SerialPort<'_> {
    fn put_byte(&self, ch: u8) {
        loop {
            let xmt = self.inb(LSR);
            if (xmt & XMTRDY) == XMTRDY {
                break;
            }
        }

        self.outb(TXR, ch)
    }

    fn get_byte(&self) -> u8 {
        loop {
            let rcv = self.inb(LSR);
            if (rcv & RCVRDY) == RCVRDY {
                return self.inb(0);
            }
        }
    }
}

impl io::Read for SerialPort<'_> {
    type Err = SvsmError;

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err> {
        for b in buf.iter_mut() {
            *b = self.get_byte();
        }

        Ok(buf.len())
    }
}

impl io::Write for SerialPort<'_> {
    type Err = SvsmError;

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err> {
        for b in buf.iter() {
            self.put_byte(*b);
        }

        Ok(buf.len())
    }
}

pub static DEFAULT_SERIAL_PORT: SerialPort<'_> = SerialPort::new(&DEFAULT_IO_DRIVER, SERIAL_PORT);
