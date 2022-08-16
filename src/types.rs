// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

pub const PAGE_SHIFT    : usize = 12;
pub const PAGE_SIZE     : usize = 1 << PAGE_SHIFT;
pub const PAGE_SIZE_2M  : usize = PAGE_SIZE * 512;

pub const SVSM_CS       : u16 = 1 * 8;
pub const SVSM_DS       : u16 = 2 * 8;
pub const SVSM_USER_CS  : u16 = 3 * 8;
pub const SVSM_USER_DS  : u16 = 4 * 8;
pub const SVSM_TSS      : u16 = 6 * 8;

pub type PhysAddr   = usize;
pub type VirtAddr   = usize;

pub const MAX_CPUS  : usize = 512;
