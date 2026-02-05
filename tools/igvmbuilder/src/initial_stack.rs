// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::mem::size_of;

use bootdefs::kernel_launch::BldrLaunchInfo;
use bootimg::BootImageInfo;
use igvm::IgvmDirectiveHeader;
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType, PAGE_SIZE_4K};
use zerocopy::IntoBytes;

use crate::gpa_map::GpaMap;
use crate::paging::InitPageTableInfo;

pub struct BootLoaderStack {
    bldr_stack: BldrLaunchInfo,
}

const _: () = assert!((size_of::<BootLoaderStack>() as u64) <= PAGE_SIZE_4K);

impl BootLoaderStack {
    pub fn new(
        gpa_map: &GpaMap,
        boot_image_info: &BootImageInfo,
        init_page_table_info: &InitPageTableInfo,
    ) -> Self {
        let bldr_stack = BldrLaunchInfo {
            kernel_entry: boot_image_info.context.entry_point,
            kernel_stack: boot_image_info.context.initial_stack,
            kernel_launch_info: boot_image_info.kernel_launch_info,
            kernel_pt_paddr: boot_image_info.kernel_page_tables_base,
            kernel_pt_count: boot_image_info.total_pt_pages,
            kernel_pdpt_paddr: boot_image_info.kernel_pdpt_paddr,
            kernel_pml4e_index: boot_image_info.kernel_pml4e_index,
            page_table_start: gpa_map.init_page_tables.get_start() as u32,
            page_table_end: gpa_map.init_page_tables.get_end() as u32,
            page_table_root: init_page_table_info.paging_root as u32,
            page_table_map_vaddr: init_page_table_info.map_vaddr,
            cpuid_addr: gpa_map.cpuid_page.get_start() as u32,
            c_bit_position: 0,
            platform_type: 0,
            _reserved: Default::default(),
        };
        Self { bldr_stack }
    }

    pub fn add_directive(
        &self,
        gpa: u64,
        compatibility_mask: u32,
        directives: &mut Vec<IgvmDirectiveHeader>,
    ) {
        let stack_data = self.bldr_stack.as_bytes();
        let mut stack_page = vec![0u8; PAGE_SIZE_4K as usize - stack_data.len()];
        stack_page.extend_from_slice(stack_data);

        directives.push(IgvmDirectiveHeader::PageData {
            gpa,
            compatibility_mask,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: stack_page,
        });
    }
}
