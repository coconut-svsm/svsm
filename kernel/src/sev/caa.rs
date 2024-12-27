// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

const _: () = assert!(core::mem::size_of::<SvsmCaa>() == 8);

/// The SVSM Calling Area (CAA)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SvsmCaa {
    pub call_pending: u8,
    mem_available: u8,
    pub no_eoi_required: u8,
    _rsvd: [u8; 5],
}

impl SvsmCaa {
    /// Returns a copy of the this CAA with the `call_pending` field cleared.
    #[inline]
    pub const fn serviced(self) -> Self {
        Self {
            call_pending: 0,
            ..self
        }
    }

    /// Returns a copy of the this CAA with the `no_eoi_required` flag updated
    #[inline]
    pub const fn update_no_eoi_required(self, no_eoi_required: u8) -> Self {
        Self {
            no_eoi_required,
            ..self
        }
    }

    /// A CAA with all of its fields set to zero.
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            call_pending: 0,
            mem_available: 0,
            no_eoi_required: 0,
            _rsvd: [0; 5],
        }
    }
}
