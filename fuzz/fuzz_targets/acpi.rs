// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com>

#![no_main]

use core::num::NonZeroUsize;
use core::sync::atomic::{AtomicUsize, Ordering};
use libfuzzer_sys::{fuzz_target, Corpus};
use std::hint::black_box;
use svsm::acpi::tables::load_fw_cpu_info;
use svsm::fw_cfg::FwCfg;
use svsm::io::IOPort;

/// A structure that emulates port I/O from a libfuzzer input.
#[derive(Debug)]
struct FuzzIo<'a> {
    data: &'a [u8],
    len: NonZeroUsize,
    pos: AtomicUsize,
}

impl<'a> FuzzIo<'a> {
    /// Create a new [`FuzzIo`] instance. Returns [`None`] if the input is
    /// empty.
    fn new(data: &'a [u8]) -> Option<Self> {
        let len = NonZeroUsize::new(data.len())?;
        let pos = AtomicUsize::new(0);
        Some(Self { data, len, pos })
    }
}

impl IOPort for FuzzIo<'_> {
    fn outb(&self, _port: u16, _value: u8) {}
    fn outw(&self, _port: u16, _value: u16) {}

    fn inb(&self, _port: u16) -> u8 {
        let pos = self.pos.load(Ordering::Relaxed);
        // SAFETY: we always keep `pos` within bounds by using the
        // modulo operation before updating it.
        let val = unsafe { *self.data.get_unchecked(pos) };
        self.pos.store((pos + 1) % self.len, Ordering::Relaxed);
        val
    }

    fn inw(&self, port: u16) -> u16 {
        let mut buf = [0u8; 2];
        buf[0] = self.inb(port);
        buf[1] = self.inb(port);
        u16::from_le_bytes(buf)
    }
}

fuzz_target!(|data: &[u8]| -> Corpus {
    let Some(io) = FuzzIo::new(data) else {
        return Corpus::Reject;
    };
    let fwcfg = FwCfg::new(&io);

    if let Ok(info) = load_fw_cpu_info(&fwcfg) {
        let _ = black_box(info);
    }

    Corpus::Keep
});
