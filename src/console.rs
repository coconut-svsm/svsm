// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::locking::SpinLock;
use core::fmt;
use crate::serial::DEFAULT_SERIAL_PORT;
use log;

pub trait ConsoleWriter {
    fn put_byte(&self, _ch : u8) { }
}

pub struct Console {
    writer : *mut dyn ConsoleWriter,
}

impl Console {
    pub fn set(&mut self, w : *mut dyn ConsoleWriter) {
        self.writer = w;
    }
}

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {

        if self.writer.is_null() {
            return Ok(());
        }

        for ch in s.bytes() {
            unsafe { (*self.writer).put_byte(ch); }
        }

        Ok(())
    }
}

pub static mut WRITER: SpinLock<Console> = SpinLock::new(unsafe { Console { writer : &mut DEFAULT_SERIAL_PORT } } );
static mut CONSOLE_INITIALIZED : bool = false;

pub fn init_console() {
    unsafe { CONSOLE_INITIALIZED = true; }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    unsafe {
        if !CONSOLE_INITIALIZED {
            return;
        }
        WRITER.lock().write_fmt(args).unwrap();
    }
}


enum ConsoleLoggerComponent {
    Uninitialized,
    Name{name : &'static str},
}

struct ConsoleLogger {
    component : ConsoleLoggerComponent,
}

impl ConsoleLogger {
    const fn uninitialized() -> ConsoleLogger {
        ConsoleLogger{component : ConsoleLoggerComponent::Uninitialized}
    }

    fn new(component : &'static str) -> ConsoleLogger {
        ConsoleLogger{component : ConsoleLoggerComponent::Name{name : component}}
    }
}

impl log::Log for ConsoleLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) == false {
            return;
        }

        // The logger being uninitialized is impossible, as that would mean it
        // wouldn't have been registered with the log library.
        let component : &'static str = match self.component {
            ConsoleLoggerComponent::Uninitialized => &"",
            ConsoleLoggerComponent::Name{name} => name,
        };

        // Log format/detail depends on the level.
        match record.metadata().level() {
            log::Level::Error | log::Level::Warn => {
                _print(format_args!("[{}] {}: {}\n",
                                    component,
                                    record.metadata().level().as_str(),
                                    record.args()));
            },

            log::Level::Info => {
                _print(format_args!("[{}] {}\n",
                                    component,
                                    record.args()));
            },

            log::Level::Debug | log::Level::Trace  => {
                _print(format_args!("[{}/{}] {} {}\n",
                                    component,
                                    record.metadata().target(),
                                    record.metadata().level().as_str(),
                                    record.args()));
            },
        };
    }

    fn flush(&self) {}
}


static mut CONSOLE_LOGGER : ConsoleLogger = ConsoleLogger::uninitialized();
static CONSOLE_LOGGER_LOCK : SpinLock<()> = SpinLock::new(());

pub fn install_console_logger(component : &'static str) {
    // The console logger gets initialized early once and becomes effectively
    // immutable henceafter. Even though not needed with the assumed
    // single-threaded setup, synchronize the initialization for universal
    // correctness.
    let console_logger_lock = CONSOLE_LOGGER_LOCK.lock();
    let console_logger = unsafe{&mut CONSOLE_LOGGER};

    if let ConsoleLoggerComponent::Name{name : _} = console_logger.component {
        // Another component has already installed the console logger.
        log::error!("Console logger reregistration from {}", component);
    }
    *console_logger = ConsoleLogger::new(component);
    drop(console_logger_lock);

    if let Err(_) = log::set_logger(console_logger) {
        // Failed to install the ConsoleLogger, presumably because something had
        // installed another logger before. No logs will appear at the console.
        // Print an error string.
        _print(format_args!("[{}]: ERROR: failed to install console logger", component));
    }

    // Log levels are to be configured via the log's library feature configuration.
    log::set_max_level(log::LevelFilter::Trace);
}

#[macro_export]
macro_rules! println {
    () => (log::info!(""));
    ($($arg:tt)*) => (log::info!($($arg)*));
}
