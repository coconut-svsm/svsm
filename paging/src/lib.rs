// SPDX-License-Identifier: MIT OR Apache-2.0

//! This crate provides page table–related functions and data structures.

#![no_std]
#![cfg_attr(verus_only, verifier::allow(unknown_automatic_derive))]
#![cfg_attr(
    verus_only,
    allow(macro_expanded_macro_exports_accessed_by_absolute_paths)
)]

pub mod address;
pub mod pagetable;
pub mod sizes;
pub mod tlb;
pub mod traits;
pub mod util;
pub mod x86_64;
