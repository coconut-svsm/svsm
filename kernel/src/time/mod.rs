// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: COCONUT-SVSM Contributors

//! Monotonic timer infrastructure for COCONUT-SVSM.
//!
//! This module provides a reliable time measurement API using SecureTSC
//! as the time source.

mod monotonic;

pub use core::time::Duration;
pub use monotonic::{
    Deadline, Instant, MONOTONIC_CLOCK, MonotonicClock, MonotonicTimer, init_monotonic_clock,
};
