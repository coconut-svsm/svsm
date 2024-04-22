// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod address_space;
pub mod alloc;
mod boxed;
pub mod guestmem;
pub mod memory;
pub mod page_visibility;
pub mod pagetable;
pub mod ptguards;
pub mod stack;
pub mod validate;
pub mod virtualrange;
pub mod vm;

pub use address_space::*;
pub use boxed::GlobalBox;
pub use guestmem::GuestPtr;
pub use memory::{valid_phys_address, writable_phys_addr};
pub use ptguards::*;

pub use pagetable::PageTablePart;

pub use alloc::{allocate_file_page, allocate_file_page_ref, PageRef};
