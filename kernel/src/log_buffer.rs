// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

use crate::console::_print;
use crate::error::SvsmError;
use crate::fs::SliceRefBuffer;
use crate::locking::SpinLock;
use crate::syscall::{ObjHandle, obj_get};
use crate::utils::immut_after_init::ImmutAfterInitCell;
use core::fmt;
use release::COCONUT_VERSION;

fn print_warning(_e: SvsmError) {
    _print(format_args!("ERROR: logging failed\n"));
}

struct LogBuffer {}

impl LogBuffer {
    const fn new() -> Self {
        Self {}
    }
}

impl fmt::Write for LogBuffer {
    /// Writes all bytes from the slice to the log buffer
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let obj_handle = ObjHandle::new(1);
        let buf = SliceRefBuffer::new(s.as_bytes());
        let fs = obj_get(obj_handle).map_err(print_warning).unwrap();
        let fs = fs
            .as_fs()
            .ok_or(SvsmError::LogError)
            .map_err(print_warning)
            .unwrap();
        let _ = fs.write_buffer(&buf).map_err(print_warning).unwrap();
        Ok(())
    }
}

static LOGGER: ImmutAfterInitCell<SpinLock<LogBuffer>> = ImmutAfterInitCell::uninit();

fn lb_write(args: fmt::Arguments<'_>) {
    use core::fmt::Write;
    if let Ok(logger) = LOGGER.try_get_inner() {
        logger.lock().write_fmt(args).unwrap();
    }
}

#[derive(Clone, Copy, Debug)]
struct BufferLogger;

impl log::Log for BufferLogger {
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
        let record_args = record.args();
        match record.metadata().level() {
            log::Level::Error | log::Level::Warn => {
                let level_str = record.metadata().level().as_str();
                lb_write(format_args!("{level_str}: {record_args}\n"));
            }

            log::Level::Info => {
                lb_write(format_args!("{record_args}\n"));
            }

            log::Level::Debug | log::Level::Trace => {
                let level_str = record.metadata().level().as_str();
                let tgt = record.metadata().target();
                lb_write(format_args!("[{tgt}] {level_str} {record_args}\n"));
            }
        };
    }

    fn flush(&self) {}
}

static BUFFER_LOGGER: BufferLogger = BufferLogger;

/// Set the log buffer as logger. This function will panic if it is
/// called more than once.
pub fn install_buffer_logger() {
    let logbuf = SpinLock::new(LogBuffer::new());
    LOGGER
        .init(logbuf)
        .expect("Failed to initialize log buffer");

    // As described in the `log` crate, this function can be called only once
    // and successive calls will return an error. Panic on that error.
    // Essentially, it handles initialization in the same way as `immut_after_init`,
    // so we can avoid using it. Therefore, the logger will be immutable after initialization.
    log::set_logger(&BUFFER_LOGGER).expect("Failed to install the BufferLogger");

    // Log levels are to be configured via the log's library feature configuration.
    log::set_max_level(log::LevelFilter::Trace);
    log::info!("COCONUT Secure Virtual Machine Service Module Version {COCONUT_VERSION}");
}
