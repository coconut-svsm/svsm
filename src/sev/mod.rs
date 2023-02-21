// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

pub mod ghcb;
pub mod msr_protocol;
pub mod secrets_page;
pub mod status;
pub mod vmsa;

pub mod utils;

pub use status::sev_status_init;
pub use status::sev_status_verify;
pub use status::{sev_es_enabled, sev_snp_enabled};
pub use utils::{RMPFlags, rmp_adjust};
pub use utils::{pvalidate, pvalidate_range, SevSnpError};
