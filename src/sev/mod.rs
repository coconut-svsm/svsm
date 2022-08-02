// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

pub mod msr_protocol;
pub mod status;
pub mod ghcb;

mod utils;

pub use utils::{PValidateError, pvalidate};
pub use status::sev_es_enabled;

use status::{sev_status_init};

pub fn sev_init() {
    sev_status_init();
}

