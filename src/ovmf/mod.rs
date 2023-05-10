// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>
//
// vim: ts=4 sw=4 et

pub mod ovmf_fw;
pub mod ovmf_meta;

pub use ovmf_fw::OvmfFw;
pub use ovmf_meta::{parse_ovmf_meta_data, print_ovmf_meta, validate_ovmf_memory, SevOVMFMetaData};
