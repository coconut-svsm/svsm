// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;

use bootlib::kernel_launch::Stage2LaunchInfo;
use igvm::IgvmDirectiveHeader;
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType, PAGE_SIZE_4K};
use zerocopy::AsBytes;

use crate::gpa_map::GpaMap;

pub struct Stage2Stack {
    stage2_stack: Stage2LaunchInfo,
}

impl Stage2Stack {
    pub fn new(gpa_map: &GpaMap) -> Self {
        let stage2_stack = Stage2LaunchInfo {
            kernel_elf_start: gpa_map.kernel_elf.get_start() as u32,
            kernel_elf_end: (gpa_map.kernel_elf.get_start() + gpa_map.kernel_elf.get_size()) as u32,
            kernel_fs_start: gpa_map.kernel_fs.get_start() as u32,
            kernel_fs_end: (gpa_map.kernel_fs.get_start() + gpa_map.kernel_fs.get_size()) as u32,
            igvm_params: gpa_map.igvm_param_block.get_start() as u32,
            padding: 0,
        };
        Self { stage2_stack }
    }

    pub fn add_directive(
        &self,
        gpa: u64,
        compatibility_mask: u32,
        directives: &mut Vec<IgvmDirectiveHeader>,
    ) -> Result<(), Box<dyn Error>> {
        let mut stage2_stack_data = self.stage2_stack.as_bytes().to_vec();
        let mut stage2_stack_page = vec![0u8; PAGE_SIZE_4K as usize - stage2_stack_data.len()];
        stage2_stack_page.append(&mut stage2_stack_data);

        if stage2_stack_page.len() > PAGE_SIZE_4K as usize {
            return Err("Stage 2 stack size exceeds 4K".into());
        }

        directives.push(IgvmDirectiveHeader::PageData {
            gpa,
            compatibility_mask,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: stage2_stack_page,
        });

        Ok(())
    }
}
