// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::mem::size_of;

use igvm::IgvmDirectiveHeader;
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType, PAGE_SIZE_4K};
use zerocopy::AsBytes;

use crate::gpa_map::GpaMap;

#[repr(C, packed(1))]
#[derive(AsBytes)]
pub struct Stage2Stack {
    pub kernel_start: u32,
    pub kernel_end: u32,
    pub filesystem_start: u32,
    pub filesystem_end: u32,
    pub igvm_param_block: u32,
    pub reserved: u32,
}

const _: () = assert!((size_of::<Stage2Stack>() as u64) <= PAGE_SIZE_4K);

impl Stage2Stack {
    pub fn new(gpa_map: &GpaMap) -> Self {
        Self {
            kernel_start: gpa_map.kernel_elf.get_start() as u32,
            kernel_end: (gpa_map.kernel_elf.get_start() + gpa_map.kernel_elf.get_size()) as u32,
            filesystem_start: gpa_map.kernel_fs.get_start() as u32,
            filesystem_end: (gpa_map.kernel_fs.get_start() + gpa_map.kernel_fs.get_size()) as u32,
            igvm_param_block: gpa_map.igvm_param_block.get_start() as u32,
            reserved: 0,
        }
    }

    pub fn add_directive(
        &self,
        gpa: u64,
        compatibility_mask: u32,
        directives: &mut Vec<IgvmDirectiveHeader>,
    ) {
        let stage2_stack_data = self.as_bytes();
        let mut stage2_stack_page = vec![0u8; PAGE_SIZE_4K as usize - stage2_stack_data.len()];
        stage2_stack_page.extend_from_slice(stage2_stack_data);

        directives.push(IgvmDirectiveHeader::PageData {
            gpa,
            compatibility_mask,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: stage2_stack_page,
        });
    }
}
