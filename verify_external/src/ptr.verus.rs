// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
use vstd::prelude::*;
use vstd::raw_ptr::*;

macro_rules! pointer_specs {
    ($mod_ident:ident, $ptr_from_data:ident, $mu:tt) => {
        #[cfg(verus_keep_ghost)]
        mod $mod_ident {
            use super::*;

            verus!{
            pub open spec fn spec_add<T: Sized>(p: *$mu T, offset: usize) -> *$mu T {
                $ptr_from_data(PtrData { addr: (p@.addr + offset * size_of::<T>()) as usize, .. p@ })
            }

            /// TODO(verus): Allow passing tracked variable to avoid all UB.
            /// # Safety:
            ///   * Avoid UB due to overflow.
            ///   * UB due to unallocated memory is only avoidable later when memory is accessed with memory permission.
            #[verifier::when_used_as_spec(spec_add)]
            pub assume_specification<T: Sized>[<*$mu T>::add](p: *$mu T, offset: usize) -> (q: *$mu T)
                requires
                    (p@.addr + offset * size_of::<T>()) <= usize::MAX,
                ensures
                    q == spec_add(p, offset)
                opens_invariants none
                no_unwind;
            }
        }
    };
}

pointer_specs!(ptr_mut_specs, ptr_mut_from_data, mut);

pointer_specs!(ptr_const_specs, ptr_from_data, const);
