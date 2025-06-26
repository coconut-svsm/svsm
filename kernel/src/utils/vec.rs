// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Red Hat, Inc
//
// Author: Tyler Fanelli <tfanelli@redhat.com>

extern crate alloc;

use alloc::{collections::TryReserveError, vec::Vec};

/// Allocate a generic Vec of a certain size and copy data from a slice into it. Alternative to the
/// `.to_vec` method for slices that panics if enough size to allocate the corresponding Vec isn't
/// available.
pub fn try_to_vec<T: Copy>(input: &[T]) -> Result<Vec<T>, TryReserveError> {
    let mut vec = Vec::new();
    let len = input.len();

    vec.try_reserve_exact(len)?;
    vec.extend_from_slice(input);

    Ok(vec)
}

/// Allocate a Vec of a certain size. Alternative to the `vec!` macro that panics if enough bytes
/// to allocate the corresponding Vec isn't available.
pub fn vec_sized<T: Default + Clone>(size: usize) -> Result<Vec<T>, TryReserveError> {
    let mut vec: Vec<T> = Vec::new();

    vec.try_reserve_exact(size)?;
    vec.resize(size, T::default());

    Ok(vec)
}
