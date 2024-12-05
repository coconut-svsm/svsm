// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Carlos López <carlos.lopez@suse.com>

#![no_main]

use libfuzzer_sys::{fuzz_target, Corpus};
use std::hint::black_box;
use svsm::platform::parse_fw_meta_data;
use svsm::types::PAGE_SIZE;

fuzz_target!(|data: &[u8]| -> Corpus {
    if data.len() != PAGE_SIZE {
        return Corpus::Reject;
    }

    let fw_meta = parse_fw_meta_data(data);
    if let Ok(meta) = fw_meta {
        let _ = black_box(meta);
    }

    Corpus::Keep
});
