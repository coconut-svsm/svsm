// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

use igvm::IgvmDirectiveHeader;
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType, PAGE_SIZE_4K};

use zerocopy::{Immutable, IntoBytes};

#[derive(Clone, Copy, Immutable, IntoBytes)]
struct PageTablePage {
    ptes: [u64; 512],
}

#[derive(Clone, Copy, Default)]
struct InitPageTables {
    pages: [PageTablePage; 2],
}

impl Default for PageTablePage {
    fn default() -> Self {
        Self { ptes: [0; 512] }
    }
}

pub fn construct_init_page_tables(
    init_page_table_gpa: u64,
    compatibility_mask: u32,
    directives: &mut Vec<IgvmDirectiveHeader>,
) {
    let mut page_tables: InitPageTables = InitPageTables::default();

    // The initial page tables comparise a single PML4E that points to a page
    // that includes entries which map the low 4 GB of the address space
    // with an identity map of 1 GB pages.
    // This PML4E is present, writable, accesed, and dirty.
    page_tables.pages[0].ptes[0] = 0x63 | (init_page_table_gpa + PAGE_SIZE_4K);

    for i in 0..4 {
        // This PTE is present, writable, accesed, dirty, and large page.
        page_tables.pages[1].ptes[i] = 0xE3 | ((i as u64) << 30);
    }

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
}
