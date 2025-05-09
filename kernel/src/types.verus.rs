// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
#[cfg(verus_keep_ghost)]
verus! {

use vstd::prelude::*;

pub broadcast group group_types_proof {
    verify_proof::bits::lemma_bit_usize_shl_values,
}

broadcast use group_types_proof;

pub broadcast proof fn lemma_page_size()
    ensures
        #[trigger] PAGE_SIZE == 0x1000,
{
    assert(1usize << 12 == 0x1000);
}

} // verus!
