// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::error::SvsmError;
use crate::io::{IOPort, Write};
use crate::locking::SpinLock;
use crate::serial::SerialPort;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use core::fmt;

/// A console device to output data
#[derive(Clone, Copy, Debug)]
enum Console {
    /// Serial port-based console
    Serial(SerialPort<'static>),
}

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}

impl Console {
    fn write_bytes(&mut self, buffer: &[u8]) {
        match self {
            Self::Serial(serial) => {
                serial.write(buffer).unwrap();
            }
        }
    }
}

/// Global console used for printing output
static WRITER: ImmutAfterInitCell<SpinLock<Console>> = ImmutAfterInitCell::uninit();

pub fn init_svsm_console(writer: &'static dyn IOPort, port: u16) -> Result<(), SvsmError> {
    let serial = SerialPort::new(writer, port);
    serial.init();

    let console = SpinLock::new(Console::Serial(serial));
    WRITER.init(console).map_err(|_| SvsmError::Console)?;
    Ok(())
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    use core::fmt::Write;
    if let Ok(writer) = WRITER.try_get_inner() {
        writer.lock().write_fmt(args).unwrap();
    }
}

/// Writes all bytes from the slice to the console
///
/// # Arguments:
///
/// * `buffer`: u8 slice with bytes to write.
pub fn console_write(buffer: &[u8]) {
    if let Ok(writer) = WRITER.try_get_inner() {
        writer.lock().write_bytes(buffer);
    }
}
