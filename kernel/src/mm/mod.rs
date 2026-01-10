// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod address_space;
pub mod alloc;
pub mod global_memory;
pub mod guestmem;
pub mod mappings;
pub mod memory;
pub mod page_visibility;
mod pagebox;
pub mod pagetable;
pub mod ptguards;
pub mod ro_after_init;
pub mod validate;
pub mod virtualrange;
pub mod vm;

pub use address_space::*;
pub use guestmem::{GuestPtr, copy_from_user, copy_to_user};
pub use memory::{valid_phys_address, writable_phys_addr};
pub use pagebox::*;
pub use ptguards::*;

pub use pagetable::PageTablePart;

pub use alloc::{PageRef, allocate_file_page};

pub use global_memory::{
    GlobalRangeGuard, map_global_range, map_global_range_2m_private, map_global_range_2m_shared,
    map_global_range_4k_private, map_global_range_4k_shared,
};
pub use mappings::{VMMappingGuard, mmap_kernel, mmap_user, munmap_kernel, munmap_user};
