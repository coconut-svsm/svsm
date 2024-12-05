// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::SpinLock;
use core::fmt;
use syscall::write_console;

#[derive(Debug, Default)]
struct ConsoleWriter {}

impl ConsoleWriter {
    const fn new() -> Self {
        Self {}
    }
}

impl fmt::Write for ConsoleWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // Ignore any errors from console writing.
        let _ = write_console(s.as_bytes());
        Ok(())
    }
}

static CONSOLE_WRITER: SpinLock<ConsoleWriter> = SpinLock::new(ConsoleWriter::new());

#[doc(hidden)]
pub fn console_print(args: fmt::Arguments<'_>) {
    use core::fmt::Write;
    CONSOLE_WRITER.lock().write_fmt(args).unwrap()
}

#[macro_export]
macro_rules! print {
        ($($arg:tt)*) => (console_print(format_args!($($arg)*)))
}

#[macro_export]
macro_rules! println {
    () => (print!("\n"));
    ($($arg:tt)*) => (print!("{}\n", format_args!($($arg)*)));
}
