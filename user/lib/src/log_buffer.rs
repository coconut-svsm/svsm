// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

use crate::SpinLock;
use crate::console_print;
use core::fmt;
use log::{Level, LevelFilter, Metadata, Record};
use syscall::SysCallError;
use syscall::write_log;

#[derive(Debug, Default)]
struct LogWriter {}

impl LogWriter {
    const fn new() -> Self {
        Self {}
    }
}

fn print_warning(_e: SysCallError) {
    console_print(format_args!("ERROR: logging failed\n"));
}

impl fmt::Write for LogWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let _ = write_log(s.as_bytes()).map_err(print_warning);
        Ok(())
    }
}

static LOG_WRITER: SpinLock<LogWriter> = SpinLock::new(LogWriter::new());

#[doc(hidden)]
pub fn log_msg(args: fmt::Arguments<'_>) {
    use core::fmt::Write;
    LOG_WRITER.lock().write_fmt(args).unwrap()
}

#[macro_export]
macro_rules! print {
        ($($arg:tt)*) => ($crate::log_msg(format_args!($($arg)*)))
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

struct UserLogger;

impl log::Log for UserLogger {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // The logger being uninitialized is impossible, as that would mean it
        // wouldn't have been registered with the log library.
        // Log format/detail depends on the level.
        match record.metadata().level() {
            Level::Error | Level::Warn => {
                println!("{}: {}", record.metadata().level().as_str(), record.args());
            }
            Level::Info => {
                println!("{}", record.args());
            }

            Level::Debug | Level::Trace => {
                println!(
                    "[{}] {} {}",
                    record.target(),
                    record.metadata().level().as_str(),
                    record.args()
                );
            }
        };
    }

    fn flush(&self) {}
}

static LOGGER: UserLogger = UserLogger;

/// Install the logger. This function is called automatically at start up
/// in `declare_main` macro. Subsequent calls will cause a panic.
pub fn install_logger() {
    // This can be called a single time, additional calls will
    // generate an error (internal behaviour of log crate)
    log::set_logger(&LOGGER).expect("Logger already initialized");
    // Log levels are to be configured via the log's library feature configuration.
    log::set_max_level(LevelFilter::Trace);
}
