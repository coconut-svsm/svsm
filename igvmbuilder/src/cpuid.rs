// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::mem::size_of;

use igvm::IgvmDirectiveHeader;
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType, PAGE_SIZE_4K};
use zerocopy::{Immutable, IntoBytes};

#[repr(C, packed(1))]
#[derive(IntoBytes, Immutable, Copy, Clone, Default)]
struct SnpCpuidLeaf {
    eax_in: u32,
    ecx_in: u32,
    xcr0: u64,
    xss: u64,
    eax_out: u32,
    ebx_out: u32,
    ecx_out: u32,
    edx_out: u32,
    reserved: u64,
}

impl SnpCpuidLeaf {
    pub fn new1(eax_in: u32) -> Self {
        Self::new2(eax_in, 0)
    }

    pub fn new2(eax_in: u32, ecx_in: u32) -> Self {
        Self::new3(eax_in, ecx_in, 0)
    }

    pub fn new3(eax_in: u32, ecx_in: u32, xcr0: u64) -> Self {
        Self {
            eax_in,
            ecx_in,
            xcr0,
            xss: 0,
            eax_out: 0,
            ebx_out: 0,
            ecx_out: 0,
            edx_out: 0,
            reserved: 0,
        }
    }
}

#[repr(C, packed(1))]
#[derive(IntoBytes, Immutable)]
pub struct SnpCpuidPage {
    count: u32,
    reserved: [u32; 3],
    cpuid_info: [SnpCpuidLeaf; 64],
}

const _: () = assert!(size_of::<SnpCpuidPage>() as u64 <= PAGE_SIZE_4K);

impl Default for SnpCpuidPage {
    fn default() -> Self {
        Self {
            count: 0,
            reserved: [0, 0, 0],
            cpuid_info: [SnpCpuidLeaf::default(); 64],
        }
    }
}

impl SnpCpuidPage {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let mut cpuid_page = SnpCpuidPage::default();
        cpuid_page.add(SnpCpuidLeaf::new1(0x8000001f))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0))?;
        cpuid_page.add(SnpCpuidLeaf::new1(1))?;
        cpuid_page.add(SnpCpuidLeaf::new1(2))?;
        cpuid_page.add(SnpCpuidLeaf::new1(4))?;
        cpuid_page.add(SnpCpuidLeaf::new2(4, 1))?;
        cpuid_page.add(SnpCpuidLeaf::new2(4, 2))?;
        cpuid_page.add(SnpCpuidLeaf::new2(4, 3))?;
        cpuid_page.add(SnpCpuidLeaf::new1(5))?;
        cpuid_page.add(SnpCpuidLeaf::new1(6))?;
        cpuid_page.add(SnpCpuidLeaf::new1(7))?;
        cpuid_page.add(SnpCpuidLeaf::new2(7, 1))?;
        cpuid_page.add(SnpCpuidLeaf::new1(11))?;
        cpuid_page.add(SnpCpuidLeaf::new2(11, 1))?;
        cpuid_page.add(SnpCpuidLeaf::new3(13, 0, 1))?;
        cpuid_page.add(SnpCpuidLeaf::new3(13, 1, 1))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x80000000))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x80000001))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x80000002))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x80000003))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x80000004))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x80000005))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x80000006))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x80000007))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x80000008))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x8000000a))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x80000019))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x8000001a))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x8000001d))?;
        cpuid_page.add(SnpCpuidLeaf::new2(0x8000001d, 1))?;
        cpuid_page.add(SnpCpuidLeaf::new2(0x8000001d, 2))?;
        cpuid_page.add(SnpCpuidLeaf::new2(0x8000001d, 3))?;
        cpuid_page.add(SnpCpuidLeaf::new1(0x8000001e))?;

        Ok(cpuid_page)
    }

    pub fn add_directive(
        &self,
        gpa: u64,
        compatibility_mask: u32,
        directives: &mut Vec<IgvmDirectiveHeader>,
    ) {
        let mut data = self.as_bytes().to_vec();
        data.resize(PAGE_SIZE_4K as usize, 0);

        directives.push(IgvmDirectiveHeader::PageData {
            gpa,
            compatibility_mask,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::CPUID_DATA,
            data,
        });
    }

    fn add(&mut self, leaf: SnpCpuidLeaf) -> Result<(), Box<dyn Error>> {
        if self.count == 64 {
            return Err("Maximum number of CPUID leaves exceeded".into());
        }
        self.cpuid_info[self.count as usize] = leaf;
        self.count += 1;
        Ok(())
    }
}
