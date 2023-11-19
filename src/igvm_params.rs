// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use crate::address::{PhysAddr, VirtAddr};
use crate::error::SvsmError;
use crate::utils::MemoryRegion;

use igvm_params::{IgvmParamBlock, IgvmParamPage};

#[derive(Clone, Debug)]
pub struct IgvmParams<'a> {
    igvm_param_block: &'a IgvmParamBlock,
    igvm_param_page: &'a IgvmParamPage,
}

impl IgvmParams<'_> {
    pub fn new(addr: VirtAddr) -> Self {
        let param_block = unsafe { &*addr.as_ptr::<IgvmParamBlock>() };
        let param_page_address = addr + param_block.param_page_offset.try_into().unwrap();
        let param_page = unsafe { &*param_page_address.as_ptr::<IgvmParamPage>() };

        Self {
            igvm_param_block: param_block,
            igvm_param_page: param_page,
        }
    }

    pub fn find_kernel_region(&self) -> Result<MemoryRegion<PhysAddr>, SvsmError> {
        let kernel_base = PhysAddr::from(self.igvm_param_block.kernel_base);
        let kernel_size: usize = self.igvm_param_block.kernel_size.try_into().unwrap();
        Ok(MemoryRegion::<PhysAddr>::new(kernel_base, kernel_size))
    }

    pub fn page_state_change_required(&self) -> bool {
        self.igvm_param_page.default_shared_pages != 0
    }

    pub fn get_cpuid_page_address(&self) -> u64 {
        self.igvm_param_block.cpuid_page as u64
    }

    pub fn get_secrets_page_address(&self) -> u64 {
        self.igvm_param_block.secrets_page as u64
    }
}
