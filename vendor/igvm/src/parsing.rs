// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Trait to help parse binary types.

use std::mem;
use zerocopy::AsBytes;
use zerocopy::FromBytes;

/// A helper trait for types that can be safely transmuted to and from byte
/// slices.
pub trait FromBytesExt: AsBytes + FromBytes {
    /// Constructs a new `Self` from an byte slice (which does not need to be
    /// aligned), returning a slice of the remaining unused bytes.
    ///
    /// Returns `None` if the byte slice is too small.
    fn read_from_prefix_split(b: &[u8]) -> Option<(Self, &[u8])>
    where
        Self: Sized,
    {
        Some((
            FromBytes::read_from_prefix(b)?,
            &b[mem::size_of::<Self>()..],
        ))
    }
}

impl<T> FromBytesExt for T where T: AsBytes + FromBytes + ?Sized {}
