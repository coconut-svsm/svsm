// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
//
// This module defines specification functions for MemoryRegion implementations
//
// How the proof works:
// - Upon entry to the SVSM (Secure Virtual Machine Monitor) kernel, we ensure there exists a set of unique
//   memory permissions that are predefined and trusted.
// - Memory permissions are unforgeable, ensuring their integrity during execution.
// - The memory region tracks the memory page permissions and their page info permissions.
// - The PageInfo's permission will be shared as read-only permissions if the page is allocated.
//   observes the same PageInfo.
// - LinearMap is correct and is used for all memory managed.
//
use crate::mm::address_space::LinearMap;
use crate::types::lemma_page_size;
use verify_external::convert::FromSpec;
use verify_proof::bits::*;
use verify_proof::frac_ptr::FracTypedPerm;
use vstd::arithmetic::mul::*;
use vstd::modes::tracked_swap;
use vstd::raw_ptr::IsExposed;

verus! {

mod alloc_spec { include!("alloc_inner.verus.rs");  }

use alloc_spec::*;

broadcast group set_len_group {
    verify_proof::set::lemma_len_filter,
    verify_proof::set::lemma_len_subset,
}

broadcast group alloc_broadcast_group {
    LinearMap::lemma_get_paddr,
    lemma_bit_usize_shl_values,
    lemma_page_size,
    set_len_group,
    //lemma_bit_u64_and_bound,
    alloc_spec::lemma_compound_neighbor,
}

broadcast use alloc_broadcast_group;

include!("alloc_info.verus.rs");

include!("alloc_free.verus.rs");

include!("alloc_perms.verus.rs");

//include!("alloc_mr.verus.rs");
include!("alloc_types.verus.rs");

} // verus!
