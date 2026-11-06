// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) SUSE LLC
//
// Author: Vaishali Thakkar <vaishali.thakkar@suse.com>

//! Monotonic clock implementation using SecureTSC.
//!
//! This module provides a monotonic clock that uses the SecureTSC facility
//! to provide reliable time measurement. The clock is initialized once at
//! boot time and provides lock-free access to the current time.

use crate::error::SvsmError;
use crate::sev::SECURE_TSC_ACCESSOR;
use crate::sev::secure_tsc::TscAccess;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use core::ops::{Add, Sub};
use core::time::Duration;

/// Pre-computed conversion constants for TSC to duration conversion.
///
/// These constants are computed once at initialization time to avoid
/// expensive division operations during time queries.
#[derive(Debug, Clone, Copy)]
struct ClockParams {
    /// TSC frequency in Hz
    freq_hz: u64,
    /// Scaled nanoseconds per tick: (10^9 << 32) / freq_hz.
    nanos_per_tick_scaled: u64,
    /// Instant corresponding to boot time
    boot_instant: Instant,
}

impl ClockParams {
    /// Create new clock parameters from the TSC frequency.
    ///
    /// # Arguments
    /// * `freq_hz` - TSC frequency in Hz
    /// * `boot_instant - Instant correspending to boot time
    fn new(freq_hz: u64, boot_instant: Instant) -> Self {
        // Pre-compute nanos_per_tick_scaled = (10^9 << 32) / freq_hz
        // This allows us to convert ticks to nanos without division:
        // nanos = (ticks * nanos_per_tick_scaled) >> 32
        let nanos_per_tick_scaled = ((1_000_000_000u128) << 32) / (freq_hz as u128);
        debug_assert!(
            nanos_per_tick_scaled <= u64::MAX as u128,
            "nanos_per_tick_scaled overflows u64 for freq_hz = {freq_hz}"
        );

        Self {
            freq_hz,
            nanos_per_tick_scaled: nanos_per_tick_scaled as u64,
            boot_instant,
        }
    }

    fn ticks_to_nanos(&self, ticks: u64) -> u64 {
        let nanos = ((ticks as u128) * (self.nanos_per_tick_scaled as u128)) >> 32;
        u64::try_from(nanos).unwrap_or(u64::MAX)
    }

    fn nanos_to_ticks(&self, nanos: u64) -> u64 {
        (self.freq_hz / 1_000_000_000) * nanos
    }
}

/// Global monotonic clock accessor.
///
/// This is the primary interface for obtaining time measurements.
/// Use `MONOTONIC_CLOCK.get_instant()` to get the current instant, or
/// `MONOTONIC_CLOCK.elapsed_since_boot()` for time since boot.
pub static MONOTONIC_CLOCK: MonotonicClock = MonotonicClock::new();

/// Monotonic clock accessor.
///
/// Provides methods to query the current time and compute durations.
/// The clock uses SecureTSC as the underlying time source.
#[derive(Debug)]
pub struct MonotonicClock {
    clock_params: ImmutAfterInitCell<ClockParams>,
}

impl MonotonicClock {
    /// Create a new MonotonicClock instance.
    pub const fn new() -> Self {
        Self {
            clock_params: ImmutAfterInitCell::uninit(),
        }
    }

    fn init(&self, cp: ClockParams) -> Result<(), SvsmError> {
        self.clock_params.init(cp)?;
        Ok(())
    }

    /// Check if the monotonic clock has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.clock_params.try_get_inner().is_ok()
    }

    /// Get the current instant.
    ///
    /// # Panics
    /// Panics if the clock has not been initialized.
    pub fn now(&self) -> Instant {
        self.try_now()
            .expect("Monotonic clock not initialized - call init_monotonic_clock() first")
    }

    /// Try to get the current instant.
    ///
    /// Returns `None` if the clock has not been initialized.
    pub fn try_now(&self) -> Option<Instant> {
        let _params = self.clock_params.try_get_inner().ok()?;
        Some(Instant::now())
    }

    /// Get the current instant.
    ///
    /// # Panics
    /// Panics if the clock has not been initialized.
    pub fn get_instant(&self) -> Instant {
        self.now()
    }

    /// Try to get the current instant.
    ///
    /// Returns `None` if the clock has not been initialized.
    pub fn try_get_instant(&self) -> Option<Instant> {
        self.try_now()
    }

    /// Get the duration elapsed since boot.
    ///
    /// # Panics
    /// Panics if the clock has not been initialized.
    pub fn elapsed_since_boot(&self) -> Duration {
        let boot_instant = self.clock_params.try_get_inner().ok().unwrap().boot_instant;
        self.now().duration_since(boot_instant)
    }

    /// Try to get the duration elapsed since boot.
    ///
    /// Returns `None` if the clock has not been initialized.
    pub fn try_elapsed_since_boot(&self) -> Option<Duration> {
        let boot_instant = self.clock_params.try_get_inner().ok()?.boot_instant;
        self.try_now().map(|i| i.duration_since(boot_instant))
    }

    /// Get the TSC frequency in Hz.
    ///
    /// Returns `None` if the clock has not been initialized.
    pub fn frequency(&self) -> Option<u64> {
        self.clock_params.try_get_inner().ok().map(|p| p.freq_hz)
    }

    /// Converts ticks to nanos
    ///
    /// Returns `None` if the clock has not been initialized.
    pub fn ticks_to_nanos(&self, ticks: u64) -> Option<u64> {
        self.clock_params
            .try_get_inner()
            .ok()
            .map(|p| p.ticks_to_nanos(ticks))
    }

    /// Converts nanos to ticks
    ///
    /// Returns `None` if the clock has not been initialized.
    pub fn nanos_to_ticks(&self, nanos: u64) -> Option<u64> {
        self.clock_params
            .try_get_inner()
            .ok()
            .map(|p| p.nanos_to_ticks(nanos))
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

/// A monotonic point in time.
///
/// An `Instant` is measured in nanoseconds since the monotonic clock's boot-time
/// epoch. The backing clock source is deliberately hidden from callers so timer
/// users can work with deadlines without depending on TSC details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant {
    ticks: u64,
}

impl Instant {
    /// Return the current Instant
    pub fn now() -> Instant {
        Self {
            ticks: SECURE_TSC_ACCESSOR.read_tsc(),
        }
    }

    /// Calculate the duration elapsed since this instant.
    ///
    /// # Panics
    /// Panics if the clock has not been initialized.
    pub fn elapsed(&self) -> Duration {
        Self::now().duration_since(*self)
    }

    /// Calculate the duration between this instant and an earlier one.
    ///
    /// If `earlier` is actually later than `self`, this returns a zero duration.
    /// # Panics
    /// Panics if the clock has not been initialized.
    pub fn duration_since(self, earlier: Instant) -> Duration {
        let diff = self.ticks.saturating_sub(earlier.ticks);
        let diff_nanos = MONOTONIC_CLOCK
            .ticks_to_nanos(diff)
            .expect("clock uninitialized");
        Duration::from_nanos(diff_nanos)
    }

    /// Calculate the duration between this instant and an earlier one,
    /// returning `None` if `earlier` is later than `self`.
    /// # Panics
    /// Panics if the clock has not been initialized.
    pub fn checked_duration_since(self, earlier: Instant) -> Option<Duration> {
        if self.ticks >= earlier.ticks {
            Some(self.duration_since(earlier))
        } else {
            None
        }
    }

    /// Add a duration, saturating at the maximum representable instant.
    /// # Panics
    /// Panics if the clock has not been initialized.
    pub fn saturating_add(self, duration: Duration) -> Self {
        let nanos = duration.as_nanos().try_into().unwrap_or(u64::MAX);
        let ticks = MONOTONIC_CLOCK
            .nanos_to_ticks(nanos)
            .expect("clock uninitialized");
        let t = self.ticks.saturating_add(ticks);
        Self { ticks: t }
    }

    /// Add a duration, returning `None` on overflow.
    /// # Panics
    /// Panics if the clock has not been initialized.
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let nanos = duration.as_nanos().try_into().ok()?;
        let ticks = MONOTONIC_CLOCK
            .nanos_to_ticks(nanos)
            .expect("clock uninitialized");
        let t = self.ticks.checked_add(ticks)?;
        Some(Self { ticks: t })
    }

    /// Subtract a duration, saturating at the monotonic epoch.
    /// # Panics
    /// Panics if the clock has not been initialized.
    pub fn saturating_sub(self, duration: Duration) -> Self {
        let nanos = duration.as_nanos().try_into().unwrap_or(u64::MAX);
        let ticks = MONOTONIC_CLOCK
            .nanos_to_ticks(nanos)
            .expect("clock uninitialized");
        let t = self.ticks.saturating_sub(ticks);
        Self { ticks: t }
    }

    /// Subtract a duration, returning `None` on underflow.
    /// # Panics
    /// Panics if the clock has not been initialized.
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        let nanos = duration.as_nanos().try_into().ok()?;
        let ticks = MONOTONIC_CLOCK
            .nanos_to_ticks(nanos)
            .expect("clock uninitialized");
        let t = self.ticks.checked_sub(ticks)?;
        Some(Self { ticks: t })
    }

    /// Return whether this instant has passed relative to `now`.
    pub const fn has_elapsed(self, now: Instant) -> bool {
        self.ticks <= now.ticks
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, rhs: Duration) -> Self::Output {
        self.checked_add(rhs)
            .expect("supplied duration causes monotonic instant overflow")
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, rhs: Duration) -> Self::Output {
        self.checked_sub(rhs)
            .expect("supplied duration is greater than monotonic instant")
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, rhs: Instant) -> Self::Output {
        self.checked_duration_since(rhs)
            .expect("supplied instant is later than self")
    }
}

/// A monotonic timer deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline(Option<Instant>);

impl Deadline {
    /// No active deadline.
    pub const NONE: Self = Self(None);

    /// Create a deadline for an absolute instant.
    pub const fn at(instant: Instant) -> Self {
        Self(Some(instant))
    }

    /// Create a deadline relative to `now`.
    pub fn after(now: Instant, duration: Duration) -> Self {
        Self::at(now.saturating_add(duration))
    }

    /// Return the deadline instant, if one is armed.
    pub const fn instant(self) -> Option<Instant> {
        self.0
    }

    /// Return whether this deadline is armed.
    pub const fn is_armed(self) -> bool {
        self.0.is_some()
    }

    /// Return whether this deadline has expired relative to `now`.
    pub const fn has_expired(self, now: Instant) -> bool {
        match self.0 {
            Some(deadline) => deadline.has_elapsed(now),
            None => false,
        }
    }

    /// Return the remaining time until this deadline relative to `now`.
    pub fn remaining(self, now: Instant) -> Option<Duration> {
        self.0.map(|deadline| deadline.duration_since(now))
    }
}

impl From<Instant> for Deadline {
    fn from(value: Instant) -> Self {
        Self::at(value)
    }
}

impl From<Option<Instant>> for Deadline {
    fn from(value: Option<Instant>) -> Self {
        Self(value)
    }
}

/// Interface implemented by monotonic timer backends.
///
/// This trait intentionally describes only the deadline API. Hardware-specific
/// plumbing such as interrupt routing and per-CPU storage can be layered behind
/// an implementation later.
pub trait MonotonicTimer {
    /// Arm the timer for `deadline`.
    fn set_deadline(&mut self, deadline: Instant);

    /// Disarm the timer.
    fn clear_deadline(&mut self);

    /// Return the currently armed deadline, if any.
    fn deadline(&self) -> Deadline;

    /// Arm or disarm the timer from a `Deadline` value.
    fn set_deadline_state(&mut self, deadline: Deadline) {
        match deadline.instant() {
            Some(instant) => self.set_deadline(instant),
            None => self.clear_deadline(),
        }
    }

    /// Return whether the currently armed deadline has expired.
    fn has_expired(&self, now: Instant) -> bool {
        self.deadline().has_expired(now)
    }
}

/// Initialize the monotonic clock.
///
/// This function should be called once during boot, after SecureTSC has been
/// configured. If SecureTSC is not enabled, this function succeeds but the
/// clock remains uninitialized (graceful degradation).
///
/// # Returns
/// - `Ok(())` on success or if SecureTSC is not available
/// - `Err(SvsmError)` if initialization fails unexpectedly
pub fn init_monotonic_clock() -> Result<(), SvsmError> {
    // Check if SecureTSC is enabled
    if !SECURE_TSC_ACCESSOR.use_secure_tsc() {
        log::info!("SecureTSC not enabled, monotonic clock not initialized");
        return Ok(());
    }

    // Get the TSC frequency
    let freq_hz = SECURE_TSC_ACCESSOR.read_tsc_frequency();
    if freq_hz == 0 {
        log::warn!("SecureTSC frequency is 0, monotonic clock not initialized");
        return Err(SvsmError::TimerError);
    }

    // Get the current instant
    let boot_instant = Instant::now();

    // Initialize clock parameters
    let params = ClockParams::new(freq_hz, boot_instant);
    MONOTONIC_CLOCK.init(params)?;

    log::info!(
        "Monotonic clock initialized: frequency = {} Hz or {} MHz",
        freq_hz,
        freq_hz / 1_000_000
    );

    Ok(())
}

#[cfg(all(test, test_in_svsm))]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_instant_ordering() {
        if MONOTONIC_CLOCK.is_initialized() {
            let earlier = Instant::now();
            let later = Instant::now();

            assert!(earlier < later);
            assert!(later > earlier);
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_duration_since_zero_when_earlier_is_later() {
        if MONOTONIC_CLOCK.is_initialized() {
            let earlier = Instant::now();
            let later = Instant::now();

            // duration_since uses saturating_sub, so should return 0
            let duration = earlier.duration_since(later);
            assert_eq!(duration, Duration::ZERO);
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_checked_duration_since() {
        if MONOTONIC_CLOCK.is_initialized() {
            let earlier = Instant::now();
            let later = Instant::now();

            assert!(later.checked_duration_since(earlier).is_some());
            assert!(earlier.checked_duration_since(later).is_none());
        }
    }

    #[test]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_deadline_expiration() {
        if MONOTONIC_CLOCK.is_initialized() {
            let now = Instant::now();
            let deadline = Deadline::after(now, Duration::from_nanos(1));

            assert!(deadline.is_armed());
            assert!(deadline.has_expired(Instant::now()));
            assert_eq!(deadline.remaining(Instant::now()), Some(Duration::ZERO));
        }
    }

    #[test]
    #[cfg(not(test_in_svsm))]
    fn test_monotonic_clock_not_initialized() {
        // MONOTONIC_CLOCK is never initialized in unit tests, so the clock
        // should report as uninitialized and try_get_instant should return None.
        let clock = MonotonicClock::new();
        assert!(!clock.is_initialized());
        assert!(clock.try_get_instant().is_none());
        assert!(clock.frequency().is_none());
    }
}
