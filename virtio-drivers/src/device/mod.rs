//! Drivers for specific VirtIO devices.

pub mod blk;
#[cfg(feature = "alloc")]
pub mod console;
pub mod socket;

pub(crate) mod common;
