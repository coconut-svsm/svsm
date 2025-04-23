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
use verus_stub::*;
verus! {

mod alloc_spec { include!("alloc_inner.verus.rs");  }

} // verus!
