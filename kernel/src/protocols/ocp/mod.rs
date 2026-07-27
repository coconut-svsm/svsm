// SPDX-License-Identifier: MIT
//
// Copyright (C) 2026 Nicola Ramacciotti
//
// Author: Nicola Ramacciotti <niko.ramak@gmail.com>

//! OCP protocol implementation (SVSM draft spec).

pub mod api;
pub mod details;
pub mod map;
pub mod requests;

pub use map::{add_ocp_object, get_first_free_index, get_object};
pub use requests::ocp_protocol_request;
