// SPDX-License-Identifier: MIT
//
// Copyright (c) SUSE LLC
//
// Author: Vaishali Thakkar <vaishali.thakkar@suse.com>

use crate::cpu::msr::{MSR_GUEST_TSC_FREQ, rdtsc, read_msr};
use crate::error::SvsmError;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

#[derive(Clone, Copy, Debug)]
pub struct SecureTscInfo {
    pub tsc_scale: u64,
    pub tsc_offset: u64,
    pub tsc_factor: u32,
}

#[derive(Debug)]
pub struct SecureTscAccessor {
    use_secure_tsc: AtomicBool,
    freq_raw: AtomicU64,
    freq_valid: AtomicBool,
    tsc_scale: AtomicU64,
    tsc_offset: AtomicU64,
    tsc_factor: AtomicU32,
    tsc_info_valid: AtomicBool,
}

impl SecureTscAccessor {
    const fn new() -> Self {
        Self {
            use_secure_tsc: AtomicBool::new(false),
            freq_raw: AtomicU64::new(0),
            freq_valid: AtomicBool::new(false),
            tsc_scale: AtomicU64::new(0),
            tsc_offset: AtomicU64::new(0),
            tsc_factor: AtomicU32::new(0),
            tsc_info_valid: AtomicBool::new(false),
        }
    }

    pub fn set_use_secure_tsc(&self, use_secure_tsc: bool) {
        self.use_secure_tsc.store(use_secure_tsc, Ordering::Relaxed)
    }

    pub fn use_secure_tsc(&self) -> bool {
        self.use_secure_tsc.load(Ordering::Relaxed)
    }

    pub fn set_tsc_info(&self, info: SecureTscInfo) {
        self.tsc_scale.store(info.tsc_scale, Ordering::Relaxed);
        self.tsc_offset.store(info.tsc_offset, Ordering::Relaxed);
        self.tsc_factor.store(info.tsc_factor, Ordering::Relaxed);
        self.tsc_info_valid.store(true, Ordering::Release);
        self.invalidate_frequency_cache();
    }

    pub fn tsc_info(&self) -> Option<SecureTscInfo> {
        if !self.use_secure_tsc() || !self.tsc_info_valid.load(Ordering::Acquire) {
            return None;
        }

        Some(SecureTscInfo {
            tsc_scale: self.tsc_scale.load(Ordering::Relaxed),
            tsc_offset: self.tsc_offset.load(Ordering::Relaxed),
            tsc_factor: self.tsc_factor.load(Ordering::Relaxed),
        })
    }

    /// Forces a re-read on next frequency query
    pub fn invalidate_frequency_cache(&self) {
        self.freq_valid.store(false, Ordering::Release);
    }
}

pub const MSR_TSC: u32 = 0x0000_0010;

pub trait TscAccess: core::fmt::Debug {
    fn read_tsc(&self) -> u64;

    /// Attempt to write the TSC must be rejected
    fn write_tsc(&self, value: u64) -> Result<(), SvsmError>;

    fn read_tsc_frequency(&self) -> u64;
}

impl TscAccess for SecureTscAccessor {
    fn read_tsc(&self) -> u64 {
        rdtsc()
    }

    fn write_tsc(&self, _value: u64) -> Result<(), SvsmError> {
        // Writing is not permitted with SecureTSC
        Err(SvsmError::InvalidAddress)
    }

    fn read_tsc_frequency(&self) -> u64 {
        if !self.use_secure_tsc() {
            return 0;
        }

        if self.freq_valid.load(Ordering::Acquire) {
            return self.freq_raw.load(Ordering::Relaxed);
        }

        let raw = read_msr(MSR_GUEST_TSC_FREQ);
        if raw != 0 {
            let factor = self.tsc_factor.load(Ordering::Relaxed) as u128;
            let adjustment = ((raw as u128) * factor) / 100_000;
            let freq = raw.saturating_sub(adjustment as u64);
            self.freq_raw.store(freq, Ordering::Relaxed);
            self.freq_valid.store(true, Ordering::Release);
            freq
        } else {
            0
        }
    }
}

pub static SECURE_TSC_ACCESSOR: SecureTscAccessor = SecureTscAccessor::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsc_accessor_creation() {
        let accessor = SecureTscAccessor::new();
        assert!(!accessor.use_secure_tsc());
        assert_eq!(accessor.read_tsc_frequency(), 0);
    }

    #[test]
    fn test_tsc_accessor_enable_disable() {
        let accessor = SecureTscAccessor::new();
        assert!(!accessor.use_secure_tsc());

        accessor.set_use_secure_tsc(true);
        assert!(accessor.use_secure_tsc());

        accessor.set_use_secure_tsc(false);
        assert!(!accessor.use_secure_tsc());
    }

    #[test]
    fn test_write_tsc_rejected() {
        let accessor = SecureTscAccessor::new();
        accessor.set_use_secure_tsc(true);

        let result = accessor.write_tsc(12345);
        assert!(result.is_err());
    }

    #[test]
    fn test_frequency_cache_invalidation() {
        let accessor = SecureTscAccessor::new();
        accessor.set_use_secure_tsc(true);

        accessor.invalidate_frequency_cache();
        assert!(!accessor.freq_valid.load(Ordering::Acquire));
    }
}
