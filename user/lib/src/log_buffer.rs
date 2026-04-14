// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

use crate::SpinLock;
use crate::console_print;
use core::fmt;
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
        ($($arg:tt)*) => (log_msg(format_args!($($arg)*)))
}

#[macro_export]
macro_rules! println {
    () => (print!("\n"));
    ($($arg:tt)*) => (print!("{}\n", format_args!($($arg)*)));
}
