// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2026 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>

use crate::console::_print;
#[cfg(feature = "enable-console-log")]
use crate::console::console_write;
use crate::error::SvsmError;
use crate::fs::{SliceRefBuffer, log_write};
use crate::locking::SpinLock;
use crate::syscall::{ObjHandle, obj_get};
use crate::types::PAGE_SIZE;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use core::fmt;
use core::fmt::Write;
use release::COCONUT_VERSION;

fn print_warning(_e: SvsmError) {
    _print(format_args!("ERROR: logging failed\n"));
}

/// Size of the early log buffer. One page is plenty: only a handful of
/// messages are emitted before the regular log buffer takes over.
const EARLY_LOG_SIZE: usize = PAGE_SIZE;

/// Prefix added to messages stored in the early log buffer. It matches the
/// prefix the idle task uses once the regular log buffer has taken over, so
/// that the log reads continuously across the hand-over.
const EARLY_LOG_PREFIX: &str = "[SVSM] ";

/// Appended to the early log buffer contents when messages were dropped
/// because the buffer ran out of space.
const EARLY_LOG_TRUNCATED: &str = "[SVSM] <early log truncated>\n";

/// A fixed size buffer holding the log messages emitted before the file
/// system is up and the regular log buffer can be used. It needs no heap and
/// no per-CPU state, so it is usable from the very beginning of kernel
/// startup. [`switch_to_log_buffer()`] copies its contents to the regular log
/// buffer, after which it is never used again.
#[derive(Debug)]
struct EarlyLogBuffer {
    buffer: [u8; EARLY_LOG_SIZE],
    fill: usize,
    /// Set when messages were dropped because the buffer is full.
    truncated: bool,
}

impl EarlyLogBuffer {
    const fn new() -> Self {
        Self {
            buffer: [0u8; EARLY_LOG_SIZE],
            fill: 0,
            truncated: false,
        }
    }

    /// Returns the bytes stored so far.
    fn contents(&self) -> &[u8] {
        &self.buffer[..self.fill]
    }
}

impl fmt::Write for EarlyLogBuffer {
    /// Keeps the earliest logs for startup diagnostics, dropping excess bytes
    /// and flagging truncation.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let src = s.as_bytes();
        let len = core::cmp::min(src.len(), EARLY_LOG_SIZE - self.fill);
        self.buffer[self.fill..self.fill + len].copy_from_slice(&src[..len]);
        self.fill += len;

        if len != src.len() {
            // End the truncated message with a newline so subsequent output
            // starts on a separate line.
            self.truncated = true;
            self.buffer[EARLY_LOG_SIZE - 1] = b'\n';
        }

        Ok(())
    }
}

static EARLY_LOG: SpinLock<EarlyLogBuffer> = SpinLock::new(EarlyLogBuffer::new());

struct LogBuffer {}

impl LogBuffer {
    const fn new() -> Self {
        Self {}
    }
}

impl fmt::Write for LogBuffer {
    /// Writes all bytes from the slice to the log buffer
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let obj_handle = ObjHandle::new(0);
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

/// Stores a message in the early log buffer. There is no task to take a name
/// from this early, so every message gets the same fixed prefix.
///
/// The message is dropped if the buffer is already locked further down the
/// call stack, for instance by an exception handler interrupting a write. No
/// IRQ-safe lock is available before per-CPU state exists, so waiting for the
/// lock here would deadlock the only CPU running at this point.
fn early_log_write(args: fmt::Arguments<'_>) {
    if let Some(mut early) = EARLY_LOG.try_lock() {
        // Writing to the early log buffer cannot fail.
        early
            .write_fmt(format_args!("{EARLY_LOG_PREFIX}{args}"))
            .unwrap();
    }
}

fn lb_write(args: fmt::Arguments<'_>) {
    match LOGGER.try_get_inner() {
        Ok(logger) => logger.lock().write_fmt(args).unwrap(),
        Err(_) => early_log_write(args),
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

/// Registers the logger to collect startup messages until
/// [`switch_to_log_buffer()`]. Earlier messages are discarded.
///
/// # Panics
///
/// Panics if a logger is already registered.
pub fn install_early_logger() {
    // As described in the `log` crate, this function can be called only once
    // and successive calls will return an error. Panic on that error.
    // Essentially, it handles initialization in the same way as `immut_after_init`,
    // so we can avoid using it. Therefore, the logger will be immutable after initialization.
    log::set_logger(&BUFFER_LOGGER).expect("Failed to install the BufferLogger");

    // Log levels are to be configured via the log's library feature configuration.
    log::set_max_level(log::LevelFilter::Trace);
    log::info!("COCONUT Secure Virtual Machine Service Module Version {COCONUT_VERSION}");
}

/// Writes `bytes` to the log file and, with the `enable-console-log` feature,
/// to the console. This bypasses the line buffer, so the caller is responsible
/// for the message prefixes and the line breaks.
fn write_log_sinks(bytes: &[u8]) {
    let _ = log_write(bytes).map_err(print_warning);

    #[cfg(feature = "enable-console-log")]
    console_write(bytes);
}

/// Activates the regular log buffer and transfers the early logs.
///
/// Requires the file system, log file, idle task, and console to be initialized.
///
/// # Panics
///
/// Panics if called more than once.
pub fn switch_to_log_buffer() {
    let logbuf = SpinLock::new(LogBuffer::new());
    LOGGER
        .init(logbuf)
        .expect("Failed to initialize log buffer");

    // Initializing the logger above routes new messages to the regular log
    // buffer, so the writes below cannot take this lock again even though
    // they can emit log messages themselves.
    let early = EARLY_LOG.lock();

    // The early log contents already carry prefixes and line breaks, so they
    // go to the log file directly.
    write_log_sinks(early.contents());
    if early.truncated {
        write_log_sinks(EARLY_LOG_TRUNCATED.as_bytes());
    }
}
