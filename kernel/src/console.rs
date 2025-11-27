// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::error::SvsmError;
use crate::io::{IOPort, Write};
use crate::locking::SpinLock;
use crate::serial::SerialPort;
use crate::utils::immut_after_init::{ImmutAfterInitCell, ImmutAfterInitResult};
use core::fmt;
use release::COCONUT_VERSION;

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
    log::info!(
        "COCONUT Secure Virtual Machine Service Module Version {}",
        COCONUT_VERSION
    );
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

#[derive(Clone, Copy, Debug)]
struct ConsoleLogger {
    name: &'static str,
}

impl ConsoleLogger {
    const fn new(name: &'static str) -> Self {
        Self { name }
    }
}

impl log::Log for ConsoleLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // The logger being uninitialized is impossible, as that would mean it
        // wouldn't have been registered with the log library.
        // Log format/detail depends on the level.
        match record.metadata().level() {
            log::Level::Error | log::Level::Warn => {
                _print(format_args!(
                    "[{}] {}: {}\n",
                    self.name,
                    record.metadata().level().as_str(),
                    record.args()
                ));
            }

            log::Level::Info => {
                _print(format_args!("[{}] {}\n", self.name, record.args()));
            }

            log::Level::Debug | log::Level::Trace => {
                _print(format_args!(
                    "[{}/{}] {} {}\n",
                    self.name,
                    record.metadata().target(),
                    record.metadata().level().as_str(),
                    record.args()
                ));
            }
        };
    }

    fn flush(&self) {}
}

static CONSOLE_LOGGER: ImmutAfterInitCell<ConsoleLogger> = ImmutAfterInitCell::uninit();

pub fn install_console_logger(component: &'static str) -> ImmutAfterInitResult<()> {
    CONSOLE_LOGGER.init_from_ref(&ConsoleLogger::new(component))?;

    if let Err(e) = log::set_logger(&*CONSOLE_LOGGER) {
        // Failed to install the ConsoleLogger, presumably because something had
        // installed another logger before. No logs will appear at the console.
        // Print an error string.
        _print(format_args!(
            "[{}]: ERROR: failed to install console logger: {:?}",
            component, e,
        ));
    }

    // Log levels are to be configured via the log's library feature configuration.
    log::set_max_level(log::LevelFilter::Trace);
    Ok(())
}

#[macro_export]
macro_rules! println {
    () => (log::info!(""));
    ($($arg:tt)*) => (log::info!($($arg)*));
}
