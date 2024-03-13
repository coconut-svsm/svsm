// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::fs;

use igvm::snp_defs::SevVmsa;
use igvm::{IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader};
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, PAGE_SIZE_4K};
use zerocopy::AsBytes;

use crate::cmd_options::CmdOptions;
use crate::page_info::PageInfo;

#[derive(PartialEq)]
enum SnpPageType {
    None,
    Normal,
    Unmeasured,
    Zero,
    Secrets,
    CpuId,
    Vmsa,
}

impl std::fmt::Display for SnpPageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SnpPageType::None => "None",
                SnpPageType::Normal => "Normal",
                SnpPageType::Unmeasured => "Unmeasured",
                SnpPageType::Zero => "Zero",
                SnpPageType::Secrets => "Secrets",
                SnpPageType::CpuId => "Cpuid",
                SnpPageType::Vmsa => "VMSA",
            }
        )
    }
}

pub struct IgvmMeasure<'a> {
    options: &'a CmdOptions,
    digest: [u8; 48],
    last_page_type: SnpPageType,
    last_gpa: u64,
    last_next_gpa: u64,
    last_len: u64,
    compatibility_mask: u32,
}

const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;

impl<'a> IgvmMeasure<'a> {
    pub fn new(options: &'a CmdOptions) -> Self {
        Self {
            options,
            digest: [0u8; 48],
            last_page_type: SnpPageType::None,
            last_gpa: 0,
            last_next_gpa: 0,
            last_len: 0,
            compatibility_mask: 0,
        }
    }

    fn find_compatibility_mask(&mut self, igvm: &IgvmFile) -> Result<(), Box<dyn Error>> {
        for platform in igvm.platforms() {
            let IgvmPlatformHeader::SupportedPlatform(platform) = platform;
            match platform.platform_type {
                IgvmPlatformType::SEV_SNP => {
                    self.compatibility_mask = platform.compatibility_mask;
                    return Ok(());
                }
                _ => continue,
            }
        }
        Err("IGVM file is not compatible with the specified platform.".into())
    }

    pub fn measure(&mut self) -> Result<[u8; 48], Box<dyn Error>> {
        let igvm_buffer = fs::read(&self.options.igvm_file).map_err(|e| {
            eprintln!("Failed to open firmware file {}", self.options.igvm_file);
            e
        })?;
        let igvm = IgvmFile::new_from_binary(igvm_buffer.as_bytes(), None)?;

        self.find_compatibility_mask(&igvm)?;

        for directive in igvm.directives() {
            match directive {
                IgvmDirectiveHeader::PageData {
                    gpa,
                    compatibility_mask,
                    flags,
                    data_type,
                    data,
                } => {
                    if (*compatibility_mask & self.compatibility_mask) != 0 {
                        self.measure_page(*gpa, flags, *data_type, data)?;
                    }
                }
                IgvmDirectiveHeader::ParameterInsert(param) => {
                    if (param.compatibility_mask & self.compatibility_mask) != 0 {
                        self.measure_page(
                            param.gpa,
                            &IgvmPageDataFlags::new().with_unmeasured(true),
                            IgvmPageDataType::NORMAL,
                            &[],
                        )?
                    }
                }
                IgvmDirectiveHeader::SnpVpContext {
                    gpa,
                    compatibility_mask,
                    vp_index: _vp_index,
                    vmsa,
                } => {
                    if (*compatibility_mask & self.compatibility_mask) != 0 {
                        self.measure_vmsa(*gpa, vmsa);
                    }
                }
                _ => (),
            }
        }
        self.log_page(SnpPageType::None, 0, 0);

        Ok(self.digest)
    }

    fn log_page(&mut self, page_type: SnpPageType, gpa: u64, len: u64) {
        if self.options.verbose {
            if (page_type != self.last_page_type) || (gpa != self.last_next_gpa) {
                if self.last_len > 0 {
                    println!(
                        "gpa {:#x} len {:#x} ({} page)",
                        self.last_gpa, self.last_len, self.last_page_type
                    );
                }
                self.last_len = len;
                self.last_gpa = gpa;
                self.last_next_gpa = gpa + len;
                self.last_page_type = page_type;
            } else {
                self.last_len += len;
                self.last_next_gpa += len;
            }
        }
    }

    fn measure_page(
        &mut self,
        gpa: u64,
        flags: &IgvmPageDataFlags,
        data_type: IgvmPageDataType,
        data: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let page_len = if flags.is_2mb_page() {
            PAGE_SIZE_2M
        } else {
            PAGE_SIZE_4K
        };
        assert!(data.is_empty() || data.len() == page_len as usize);

        if data.is_empty() {
            for page_offset in (0..page_len).step_by(PAGE_SIZE_4K as usize) {
                self.measure_page_4k(gpa + page_offset, flags, data_type, &vec![]);
            }
        } else {
            for (index, page_data) in data.chunks(PAGE_SIZE_4K as usize).enumerate() {
                self.measure_page_4k(
                    gpa + index as u64 * PAGE_SIZE_4K,
                    flags,
                    data_type,
                    &page_data.to_vec(),
                );
            }
        }
        Ok(())
    }

    fn measure_page_4k(
        &mut self,
        gpa: u64,
        flags: &IgvmPageDataFlags,
        data_type: IgvmPageDataType,
        data: &Vec<u8>,
    ) {
        let page_info = match data_type {
            IgvmPageDataType::NORMAL => {
                if flags.unmeasured() {
                    self.log_page(SnpPageType::Unmeasured, gpa, PAGE_SIZE_4K);
                    Some(PageInfo::new_unmeasured_page(self.digest, gpa))
                } else if data.is_empty() {
                    self.log_page(SnpPageType::Zero, gpa, PAGE_SIZE_4K);
                    Some(PageInfo::new_zero_page(self.digest, gpa))
                } else {
                    self.log_page(SnpPageType::Normal, gpa, data.len() as u64);
                    Some(PageInfo::new_normal_page(self.digest, gpa, data))
                }
            }
            IgvmPageDataType::SECRETS => {
                self.log_page(SnpPageType::Secrets, gpa, PAGE_SIZE_4K);
                Some(PageInfo::new_secrets_page(self.digest, gpa))
            }
            IgvmPageDataType::CPUID_DATA => {
                self.log_page(SnpPageType::CpuId, gpa, PAGE_SIZE_4K);
                Some(PageInfo::new_cpuid_page(self.digest, gpa))
            }
            IgvmPageDataType::CPUID_XF => {
                self.log_page(SnpPageType::CpuId, gpa, PAGE_SIZE_4K);
                Some(PageInfo::new_cpuid_page(self.digest, gpa))
            }
            _ => None,
        };
        if let Some(page_info) = page_info {
            self.digest = page_info.update_hash();
        }
    }

    fn measure_vmsa(&mut self, gpa: u64, vmsa: &SevVmsa) {
        let mut vmsa_page = vmsa.as_bytes().to_vec();
        vmsa_page.resize(PAGE_SIZE_4K as usize, 0);
        self.log_page(SnpPageType::Vmsa, gpa, PAGE_SIZE_4K);
        let page_info = PageInfo::new_vmsa_page(self.digest, gpa, &vmsa_page);
        self.digest = page_info.update_hash();
    }
}
