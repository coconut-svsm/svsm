// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;

use igvm::snp_defs::SevVmsa;
use igvm::{IgvmDirectiveHeader, IgvmFile};
use igvm_defs::{IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, PAGE_SIZE_4K};
use sha2::{Digest, Sha256};
use zerocopy07::AsBytes;

use crate::page_info::PageInfo;

#[derive(Copy, Clone)]
pub enum IgvmMeasureError {
    InvalidVmsaCount,
    InvalidVmsaGpa,
    InvalidVmsaCr0,
    InvalidDebugSwap,
    InvalidVmsaOrder,
    IDBlockMismatch([u8; 48]),
}

impl std::fmt::Display for IgvmMeasureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IgvmMeasureError::InvalidVmsaCount => {
                write!(
                    f,
                    "KVM check failure: More than one VMSA has been provided \
                    in the IGVM file. QEMU/KVM only supports setting of the \
                    VMSA for the first virtual CPU."
                )
            }
            IgvmMeasureError::InvalidVmsaGpa => {
                write!(
                    f,
                    "KVM check failure: The GPA for the VMSA does not match \
                    the address hardcoded in KVM. KVM will always populate \
                    the VMSA at GPA 0xFFFFFFFFF000. The IGVM file must set \
                    the GPA for the VMSA to this address."
                )
            }
            IgvmMeasureError::InvalidVmsaCr0 => {
                write!(
                    f,
                    "KVM check failure: CR0 in the VMSA in the IGVM file is \
                    not set to 0x31. The value of CR0 is overridden by KVM \
                    during initial measurement. Therefore the IGVM file must \
                    be configured to match the value set by KVM."
                )
            }
            IgvmMeasureError::InvalidDebugSwap => {
                write!(
                    f,
                    "KVM check failure: DEBUG_SWAP(0x20) is not set in \
                    sev_features in the VMSA file. This feature is \
                    automatically applied by KVM during the initial \
                    measurement so it must be specified in the VMSA in \
                    the IGVM file in order to match."
                )
            }
            IgvmMeasureError::InvalidVmsaOrder => {
                write!(
                    f,
                    "KVM check failure: The VMSA must be the final page \
                        directive in the IGVM file. \
                        This is because QEMU/KVM measures the VMSA page \
                        when the measurement is finalized and not in the \
                        order specified in the IGVM file. Make sure your \
                        IGVM file places the VMSA directive after any other \
                        measured or unmeasured page directives."
                )
            }
            IgvmMeasureError::IDBlockMismatch(expected) => {
                write!(
                    f,
                    "An ID block has been provided in the IGVM file but the \
                        calculated measurement does not match the expected \
                        measurement in the ID block. \n\
                        Expected: "
                )?;
                expected.iter().try_for_each(|val| write!(f, "{:02X}", val))
            }
        }
    }
}
impl std::fmt::Debug for IgvmMeasureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
impl Error for IgvmMeasureError {}

#[derive(PartialEq, Debug)]
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

#[derive(Debug)]
struct IgvmMeasureContext {
    digest_snp: [u8; 48],
    digest_es: Sha256,
}

impl Default for IgvmMeasureContext {
    fn default() -> Self {
        Self {
            digest_snp: [0u8; 48],
            digest_es: Sha256::default(),
        }
    }
}

#[derive(Debug)]
pub struct IgvmMeasure {
    show_progress: bool,
    check_kvm: bool,
    native_zero: bool,
    digest: Vec<u8>,
    last_page_type: SnpPageType,
    last_gpa: u64,
    last_next_gpa: u64,
    last_len: u64,
    compatibility_mask: u32,
    vmsa_count: u32,
    id_block_ld: Option<[u8; 48]>,
    platform: IgvmPlatformType,
}

const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;

impl IgvmMeasure {
    pub fn measure(
        show_progress: bool,
        check_kvm: bool,
        native_zero: bool,
        compatibility_mask: u32,
        platform: IgvmPlatformType,
        igvm: &IgvmFile,
    ) -> Result<Self, Box<dyn Error>> {
        let mut result = Self {
            show_progress,
            check_kvm,
            native_zero,
            digest: vec![],
            last_page_type: SnpPageType::None,
            last_gpa: 0,
            last_next_gpa: 0,
            last_len: 0,
            compatibility_mask,
            vmsa_count: 0,
            id_block_ld: None,
            platform,
        };
        result.do_measure(igvm)?;
        Ok(result)
    }

    pub fn check_id_block(&self) -> Result<(), IgvmMeasureError> {
        if let Some(expected_ld) = self.id_block_ld {
            let mut ld = [0u8; 48];
            ld.copy_from_slice(self.digest());
            if expected_ld != ld {
                return Err(IgvmMeasureError::IDBlockMismatch(expected_ld));
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> &Vec<u8> {
        &self.digest
    }

    fn do_measure(&mut self, igvm: &IgvmFile) -> Result<(), Box<dyn Error>> {
        let mut ctx = IgvmMeasureContext::default();

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
                        self.measure_page(&mut ctx, *gpa, flags, *data_type, data)?;
                    }
                }
                IgvmDirectiveHeader::ParameterInsert(param) => {
                    if (param.compatibility_mask & self.compatibility_mask) != 0 {
                        if self.check_kvm && (self.vmsa_count > 0) {
                            return Err(IgvmMeasureError::InvalidVmsaOrder.into());
                        }
                        self.measure_page(
                            &mut ctx,
                            param.gpa,
                            &IgvmPageDataFlags::new().with_unmeasured(true),
                            IgvmPageDataType::NORMAL,
                            &[],
                        )?;
                    }
                }
                IgvmDirectiveHeader::SnpVpContext {
                    gpa,
                    compatibility_mask,
                    vp_index: _vp_index,
                    vmsa,
                } => {
                    self.measure_vmsa(&mut ctx, *gpa, *compatibility_mask, vmsa)?;
                }
                IgvmDirectiveHeader::SnpIdBlock {
                    compatibility_mask,
                    ld,
                    ..
                } => {
                    if (self.compatibility_mask & compatibility_mask) != 0 {
                        self.id_block_ld = Some(*ld);
                    }
                }
                _ => (),
            }
        }
        self.log_page(SnpPageType::None, 0, 0);

        if (self.platform == IgvmPlatformType::SEV_ES) || (self.platform == IgvmPlatformType::SEV) {
            self.digest = ctx.digest_es.finalize_reset().to_vec();
        } else {
            self.digest = ctx.digest_snp.to_vec();
        }
        Ok(())
    }

    fn log_page(&mut self, page_type: SnpPageType, gpa: u64, len: u64) {
        if self.show_progress {
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
        ctx: &mut IgvmMeasureContext,
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
                self.measure_page_4k(ctx, gpa + page_offset, flags, data_type, &vec![]);
            }
        } else {
            for (index, page_data) in data.chunks(PAGE_SIZE_4K as usize).enumerate() {
                self.measure_page_4k(
                    ctx,
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
        ctx: &mut IgvmMeasureContext,
        gpa: u64,
        flags: &IgvmPageDataFlags,
        data_type: IgvmPageDataType,
        data: &Vec<u8>,
    ) {
        if self.platform == IgvmPlatformType::SEV_SNP {
            let page_info = match data_type {
                IgvmPageDataType::NORMAL => {
                    if flags.unmeasured() {
                        self.log_page(SnpPageType::Unmeasured, gpa, PAGE_SIZE_4K);
                        Some(PageInfo::new_unmeasured_page(ctx.digest_snp, gpa))
                    } else if data.is_empty() {
                        if self.native_zero {
                            self.log_page(SnpPageType::Zero, gpa, PAGE_SIZE_4K);
                            Some(PageInfo::new_zero_page(ctx.digest_snp, gpa))
                        } else {
                            self.log_page(SnpPageType::Normal, gpa, PAGE_SIZE_4K);
                            Some(PageInfo::new_normal_page(
                                ctx.digest_snp,
                                gpa,
                                &vec![0u8; PAGE_SIZE_4K as usize],
                            ))
                        }
                    } else {
                        self.log_page(SnpPageType::Normal, gpa, data.len() as u64);
                        Some(PageInfo::new_normal_page(ctx.digest_snp, gpa, data))
                    }
                }
                IgvmPageDataType::SECRETS => {
                    self.log_page(SnpPageType::Secrets, gpa, PAGE_SIZE_4K);
                    Some(PageInfo::new_secrets_page(ctx.digest_snp, gpa))
                }
                IgvmPageDataType::CPUID_DATA => {
                    self.log_page(SnpPageType::CpuId, gpa, PAGE_SIZE_4K);
                    Some(PageInfo::new_cpuid_page(ctx.digest_snp, gpa))
                }
                IgvmPageDataType::CPUID_XF => {
                    self.log_page(SnpPageType::CpuId, gpa, PAGE_SIZE_4K);
                    Some(PageInfo::new_cpuid_page(ctx.digest_snp, gpa))
                }
                _ => None,
            };
            if let Some(page_info) = page_info {
                ctx.digest_snp = page_info.update_hash();
            }
        } else {
            self.log_page(SnpPageType::Normal, gpa, PAGE_SIZE_4K);
            ctx.digest_es.update(data);
        }
    }

    fn check_vmsa(&self, gpa: u64, vmsa: &SevVmsa) -> Result<(), IgvmMeasureError> {
        if self.check_kvm {
            if self.vmsa_count > 0 {
                return Err(IgvmMeasureError::InvalidVmsaCount);
            }
            if gpa != 0xFFFFFFFFF000 {
                return Err(IgvmMeasureError::InvalidVmsaGpa);
            }
            if vmsa.cr0 != 0x31 {
                return Err(IgvmMeasureError::InvalidVmsaCr0);
            }
            if vmsa.sev_features.debug_swap() {
                return Err(IgvmMeasureError::InvalidDebugSwap);
            }
        }
        Ok(())
    }

    fn measure_vmsa(
        &mut self,
        ctx: &mut IgvmMeasureContext,
        gpa: u64,
        _compatibility_mask: u32,
        vmsa: &SevVmsa,
    ) -> Result<(), Box<dyn Error>> {
        self.check_vmsa(gpa, vmsa)?;

        let mut vmsa_page = vmsa.as_bytes().to_vec();
        vmsa_page.resize(PAGE_SIZE_4K as usize, 0);
        self.log_page(SnpPageType::Vmsa, gpa, PAGE_SIZE_4K);
        if self.platform == IgvmPlatformType::SEV_SNP {
            let page_info = PageInfo::new_vmsa_page(ctx.digest_snp, gpa, &vmsa_page);
            ctx.digest_snp = page_info.update_hash();
        } else {
            ctx.digest_es.update(vmsa_page.as_bytes());
        }
        self.vmsa_count += 1;

        Ok(())
    }
}
