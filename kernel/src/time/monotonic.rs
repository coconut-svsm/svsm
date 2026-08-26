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
    /// TSC value at boot time (when clock was initialized)
    boot_tsc: u64,
}

impl ClockParams {
    /// Create new clock parameters from the TSC frequency.
    ///
    /// # Arguments
    /// * `freq_hz` - TSC frequency in Hz
    /// * `boot_tsc` - TSC value at initialization time
    fn new(freq_hz: u64, boot_tsc: u64) -> Self {
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
            boot_tsc,
        }
    }

    #[inline]
    fn ticks_to_duration(&self, ticks: u64) -> Duration {
        let nanos = ((ticks as u128) * (self.nanos_per_tick_scaled as u128)) >> 32;
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

/// Global clock parameters, initialized once at boot.
static CLOCK_PARAMS: ImmutAfterInitCell<ClockParams> = ImmutAfterInitCell::uninit();

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
    _private: (),
}

impl MonotonicClock {
    /// Create a new MonotonicClock instance.
    pub const fn new() -> Self {
        Self { _private: () }
    }

    /// Check if the monotonic clock has been initialized.
    #[inline]
    pub fn is_initialized(&self) -> bool {
        CLOCK_PARAMS.try_get_inner().is_ok()
    }

    /// Get the current instant.
    ///
    /// # Panics
    /// Panics if the clock has not been initialized.
    #[inline]
    pub fn now(&self) -> Instant {
        self.try_now()
            .expect("Monotonic clock not initialized - call init_monotonic_clock() first")
    }

    /// Try to get the current instant.
    ///
    /// Returns `None` if the clock has not been initialized.
    #[inline]
    pub fn try_now(&self) -> Option<Instant> {
        let params = CLOCK_PARAMS.try_get_inner().ok()?;
        let tsc = SECURE_TSC_ACCESSOR.read_tsc();

        // Calculate ticks since boot, handling potential wraparound
        let duration_since_boot = params.ticks_to_duration(tsc.wrapping_sub(params.boot_tsc));

        Some(Instant::from_duration_since_boot(duration_since_boot))
    }

    /// Get the current instant.
    ///
    /// # Panics
    /// Panics if the clock has not been initialized.
    #[inline]
    pub fn get_instant(&self) -> Instant {
        self.now()
    }

    /// Try to get the current instant.
    ///
    /// Returns `None` if the clock has not been initialized.
    #[inline]
    pub fn try_get_instant(&self) -> Option<Instant> {
        self.try_now()
    }

    /// Get the duration elapsed since boot.
    ///
    /// # Panics
    /// Panics if the clock has not been initialized.
    #[inline]
    pub fn elapsed_since_boot(&self) -> Duration {
        self.now().duration_since_boot()
    }

    /// Try to get the duration elapsed since boot.
    ///
    /// Returns `None` if the clock has not been initialized.
    #[inline]
    pub fn try_elapsed_since_boot(&self) -> Option<Duration> {
        self.try_now().map(|i| i.duration_since_boot())
    }

    /// Get the TSC frequency in Hz.
    ///
    /// Returns `None` if the clock has not been initialized.
    pub fn frequency(&self) -> Option<u64> {
        CLOCK_PARAMS.try_get_inner().ok().map(|p| p.freq_hz)
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
    nanos_since_boot: u64,
}

impl Instant {
    /// The monotonic epoch.
    pub const ZERO: Self = Self {
        nanos_since_boot: 0,
    };

    /// Create an instant from a raw nanosecond value since boot.
    ///
    /// This is intended for code that persists or exchanges monotonic deadlines
    /// in their raw representation.
    #[inline]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self {
            nanos_since_boot: nanos,
        }
    }

    /// Return the raw nanosecond value since boot.
    #[inline]
    pub const fn as_nanos(self) -> u64 {
        self.nanos_since_boot
    }

    /// Create an instant from a duration since boot.
    #[inline]
    pub fn from_duration_since_boot(duration: Duration) -> Self {
        Self::from_nanos(duration.as_nanos().try_into().unwrap_or(u64::MAX))
    }

    /// Return the duration since boot represented by this instant.
    #[inline]
    pub const fn duration_since_boot(self) -> Duration {
        Duration::from_nanos(self.nanos_since_boot)
    }

    /// Calculate the duration elapsed since this instant.
    ///
    /// # Panics
    /// Panics if the clock has not been initialized.
    #[inline]
    pub fn elapsed(&self) -> Duration {
        MONOTONIC_CLOCK.now().duration_since(*self)
    }

    /// Try to calculate the duration elapsed since this instant.
    ///
    /// Returns `None` if the clock has not been initialized.
    #[inline]
    pub fn try_elapsed(&self) -> Option<Duration> {
        MONOTONIC_CLOCK
            .try_now()
            .map(|now| now.duration_since(*self))
    }

    /// Calculate the duration between this instant and an earlier one.
    ///
    /// If `earlier` is actually later than `self`, this returns a zero duration.
    #[inline]
    pub const fn duration_since(self, earlier: Instant) -> Duration {
        Duration::from_nanos(
            self.nanos_since_boot
                .saturating_sub(earlier.nanos_since_boot),
        )
    }

    /// Calculate the duration between this instant and an earlier one,
    /// returning `None` if `earlier` is later than `self`.
    #[inline]
    pub const fn checked_duration_since(self, earlier: Instant) -> Option<Duration> {
        if self.nanos_since_boot >= earlier.nanos_since_boot {
            Some(self.duration_since(earlier))
        } else {
            None
        }
    }

    /// Add a duration, saturating at the maximum representable instant.
    #[inline]
    pub fn saturating_add(self, duration: Duration) -> Self {
        Self::from_nanos(
            self.nanos_since_boot
                .saturating_add(duration.as_nanos().try_into().unwrap_or(u64::MAX)),
        )
    }

    /// Add a duration, returning `None` on overflow.
    #[inline]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        Some(Self::from_nanos(
            self.nanos_since_boot
                .checked_add(duration.as_nanos().try_into().ok()?)?,
        ))
    }

    /// Subtract a duration, saturating at the monotonic epoch.
    #[inline]
    pub fn saturating_sub(self, duration: Duration) -> Self {
        Self::from_nanos(
            self.nanos_since_boot
                .saturating_sub(duration.as_nanos().try_into().unwrap_or(u64::MAX)),
        )
    }

    /// Subtract a duration, returning `None` on underflow.
    #[inline]
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        Some(Self::from_nanos(
            self.nanos_since_boot
                .checked_sub(duration.as_nanos().try_into().ok()?)?,
        ))
    }

    /// Return whether this instant has passed relative to `now`.
    #[inline]
    pub const fn has_elapsed(self, now: Instant) -> bool {
        self.nanos_since_boot <= now.nanos_since_boot
    }

    /// Convert this instant to a Duration representing time since boot.
    #[inline]
    pub const fn as_duration(self) -> Duration {
        self.duration_since_boot()
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
    #[inline]
    pub const fn at(instant: Instant) -> Self {
        Self(Some(instant))
    }

    /// Create a deadline relative to `now`.
    #[inline]
    pub fn after(now: Instant, duration: Duration) -> Self {
        Self::at(now.saturating_add(duration))
    }

    /// Return the deadline instant, if one is armed.
    #[inline]
    pub const fn instant(self) -> Option<Instant> {
        self.0
    }

    /// Return whether this deadline is armed.
    #[inline]
    pub const fn is_armed(self) -> bool {
        self.0.is_some()
    }

    /// Return whether this deadline has expired relative to `now`.
    #[inline]
    pub const fn has_expired(self, now: Instant) -> bool {
        match self.0 {
            Some(deadline) => deadline.has_elapsed(now),
            None => false,
        }
    }

    /// Return the remaining time until this deadline relative to `now`.
    #[inline]
    pub const fn remaining(self, now: Instant) -> Option<Duration> {
        match self.0 {
            Some(deadline) => Some(deadline.duration_since(now)),
            None => None,
        }
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
        return Ok(());
    }

    // Read the current TSC as boot time
    let boot_tsc = SECURE_TSC_ACCESSOR.read_tsc();

    // Initialize clock parameters
    let params = ClockParams::new(freq_hz, boot_tsc);
    CLOCK_PARAMS.init(params)?;

    log::info!("Monotonic clock initialized: frequency = {freq_hz} MHz");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instant_ordering() {
        let earlier = Instant::from_nanos(100);
        let later = Instant::from_nanos(200);

        assert!(earlier < later);
        assert!(later > earlier);
        assert_eq!(earlier, Instant::from_nanos(100));
    }

    #[test]
    fn test_instant_nanos() {
        let instant = Instant::from_nanos(12345);
        assert_eq!(instant.as_nanos(), 12345);
    }

    #[test]
    fn test_clock_params_creation() {
        let params = ClockParams::new(1_000_000_000, 0); // 1 GHz
        assert_eq!(params.freq_hz, 1_000_000_000);
        assert_eq!(params.boot_tsc, 0);
        // nanos_per_tick_scaled should be approximately (10^9 << 32) / 10^9 = 2^32
        assert!(params.nanos_per_tick_scaled > 0);
    }

    #[test]
    fn test_duration_since_zero_when_earlier_is_later() {
        let earlier = Instant::from_nanos(200);
        let later = Instant::from_nanos(100);

        // duration_since uses saturating_sub, so should return 0
        let duration = later.duration_since(earlier);
        assert_eq!(duration, Duration::ZERO);
    }

    #[test]
    fn test_checked_duration_since() {
        let earlier = Instant::from_nanos(100);
        let later = Instant::from_nanos(200);

        assert!(later.checked_duration_since(earlier).is_some());
        assert!(earlier.checked_duration_since(later).is_none());
    }

    #[test]
    fn test_deadline_expiration() {
        let now = Instant::from_nanos(100);
        let deadline = Deadline::after(now, Duration::from_nanos(50));

        assert!(deadline.is_armed());
        assert!(!deadline.has_expired(Instant::from_nanos(149)));
        assert!(deadline.has_expired(Instant::from_nanos(150)));
        assert_eq!(
            deadline.remaining(Instant::from_nanos(125)),
            Some(Duration::from_nanos(25))
        );
    }

    #[test]
    fn test_monotonic_clock_not_initialized() {
        // CLOCK_PARAMS is never initialized in unit tests, so the clock
        // should report as uninitialized and try_get_instant should return None.
        let clock = MonotonicClock::new();
        assert!(!clock.is_initialized());
        assert!(clock.try_get_instant().is_none());
        assert!(clock.frequency().is_none());
    }
}
