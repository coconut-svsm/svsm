// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::io::{IOPort, DEFAULT_IO_DRIVER};

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

pub trait Terminal {
    fn put_byte(&self, _ch: u8) {}
    fn get_byte(&self) -> u8 {
        0
    }
}

pub struct SerialPort<'a> {
    pub driver: &'a dyn IOPort,
    pub port: u16,
}

impl<'a> SerialPort<'a> {
    pub fn new(driver: &'a dyn IOPort, p: u16) -> Self {
        SerialPort { driver, port: p }
    }

    pub fn init(&self) {
        let divisor: u32 = 115200 / BAUD;
        let driver = &self.driver;
        let port = self.port;

        driver.outb(port + LCR, 0x3); // 8n1
        driver.outb(port + IER, 0); // No Interrupt
        driver.outb(port + FCR, 0); // No FIFO
        driver.outb(port + MCR, 0x3); // DTR + RTS

        let c = driver.inb(port + LCR);
        driver.outb(port + LCR, c | DLAB);
        driver.outb(port + DLL, (divisor & 0xff) as u8);
        driver.outb(port + DLH, ((divisor >> 8) & 0xff) as u8);
        driver.outb(port + LCR, c & !DLAB);
    }
}

impl<'a> Terminal for SerialPort<'a> {
    fn put_byte(&self, ch: u8) {
        let driver = &self.driver;
        let port = self.port;

        loop {
            let xmt = driver.inb(port + LSR);
            if (xmt & XMTRDY) == XMTRDY {
                break;
            }
        }

        driver.outb(port + TXR, ch)
    }

    fn get_byte(&self) -> u8 {
        let driver = &self.driver;
        let port = self.port;

        loop {
            let rcv = driver.inb(port + LSR);
            if (rcv & RCVRDY) == RCVRDY {
                return driver.inb(port);
            }
        }
    }
}

pub static mut DEFAULT_SERIAL_PORT: SerialPort = SerialPort {
    driver: &DEFAULT_IO_DRIVER,
    port: SERIAL_PORT,
};
