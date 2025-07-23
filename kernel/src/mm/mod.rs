// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod access;
pub mod address_space;
pub mod alloc;
pub mod global_memory;
pub mod mappings;
pub mod memory;
pub mod page_visibility;
mod pagebox;
pub mod pagetable;
pub mod validate;
pub mod virtualrange;
pub mod vm;

pub use address_space::*;
pub use memory::{valid_phys_address, writable_phys_addr};
pub use pagebox::*;

pub use pagetable::PageTablePart;

pub use alloc::{allocate_file_page, PageRef};

pub use global_memory::{
    map_global_range, map_global_range_2m_private, map_global_range_2m_shared,
    map_global_range_4k_private, map_global_range_4k_shared, GlobalRangeGuard,
};
pub use mappings::{mmap_kernel, mmap_user, munmap_kernel, munmap_user, VMMappingGuard};
