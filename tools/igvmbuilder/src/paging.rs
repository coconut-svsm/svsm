// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use igvm::IgvmDirectiveHeader;
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType, PAGE_SIZE_4K};

use zerocopy::{Immutable, IntoBytes};

use crate::gpa_map::INIT_PT_COUNT;
use crate::igvm_builder::COMPATIBILITY_MASK;

#[derive(Clone, Debug, Default)]
pub struct InitPageTableInfo {
    pub paging_root: u64,
    pub map_vaddr: u64,
}

#[derive(Clone, Copy, Immutable, IntoBytes)]
struct PageTablePage {
    ptes: [u64; 512],
}

#[derive(Clone, Copy, Default)]
struct InitPageTables {
    pages: [PageTablePage; INIT_PT_COUNT],
}

impl Default for PageTablePage {
    fn default() -> Self {
        Self { ptes: [0; 512] }
    }
}

pub fn setup_init_page_tables(
    init_page_table_gpa: u64,
    compatibility_mask: u32,
    directives: &mut Vec<IgvmDirectiveHeader>,
) -> InitPageTableInfo {
    if COMPATIBILITY_MASK.contains(compatibility_mask) {
        construct_init_page_tables(init_page_table_gpa, compatibility_mask, directives)
    } else {
        InitPageTableInfo::default()
    }
}

fn construct_init_page_tables(
    init_page_table_gpa: u64,
    compatibility_mask: u32,
    directives: &mut Vec<IgvmDirectiveHeader>,
) -> InitPageTableInfo {
    let mut page_tables: InitPageTables = InitPageTables::default();

    // Construct a PTE mask that represents writable, accessed, and dirty.
    let pte_mask: u64 = 0x63;

    // The initial page tables comprise four pages: one PML4E that points to
    // a page that includes entries which map the low 4 GB of the address space
    // with an identity map of 1 GB pages, and which also contains pages
    // sufficient to map 2 MB worth of data using 4 KB PTEs.  These pages are
    // constructed in reverse order, so the first page is the placeholder
    // for the 4 KB PTEs, and the last page is the paging root.
    page_tables.pages[3].ptes[0] = pte_mask | (init_page_table_gpa + 2 * PAGE_SIZE_4K);

    for i in 0..4 {
        // This PTE is present, writable, accessed, dirty, and large page.
        page_tables.pages[2].ptes[i] = 0xE3 | ((i as u64) << 30);
    }

    page_tables.pages[2].ptes[4] = pte_mask | (init_page_table_gpa + PAGE_SIZE_4K);
    page_tables.pages[1].ptes[0] = pte_mask | init_page_table_gpa;

    for (i, data) in page_tables.pages.iter().enumerate() {
        // Allocate a byte vector to contain a copy of the initial page table
        // data.
        let mut page_table_data = Vec::<u8>::new();
        page_table_data.extend_from_slice(data.as_bytes());

        directives.push(IgvmDirectiveHeader::PageData {
            gpa: init_page_table_gpa + (i as u64) * PAGE_SIZE_4K,
            compatibility_mask,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: page_table_data,
        });
    }

    // The paging root is the last of the pages.
    let paging_root = init_page_table_gpa + 3 * PAGE_SIZE_4K;

    // The virtual address used for mappings is 4 GB, immediately following the
    // identity map of the low 4 GB that was established.
    let map_vaddr: u64 = 4 << 30;

    InitPageTableInfo {
        paging_root,
        map_vaddr,
    }
}
