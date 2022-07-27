// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

pub const PAGE_SIZE     : usize = 4096;
pub const PAGE_SIZE_2M  : usize = PAGE_SIZE * 512;

pub const SVSM_CS  : u16 = 8;
pub const SVSM_DS  : u16 = 16;

pub type PhysAddr   = usize;
pub type VirtAddr   = usize;

