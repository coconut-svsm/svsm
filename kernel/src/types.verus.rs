// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Ziqiao Zhou <ziqiaozhou@microsoft.com>
verus! {

pub broadcast group group_types_proof {
    verify_proof::bits::lemma_bit_usize_shl_values,
}

broadcast use group_types_proof;

} // verus!
