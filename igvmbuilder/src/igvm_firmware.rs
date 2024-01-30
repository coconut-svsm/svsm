// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::error::Error;
use std::fs;

use igvm::snp_defs::SevVmsa;
use igvm::{IgvmDirectiveHeader, IgvmFile};
use igvm_defs::{IgvmPageDataType, PAGE_SIZE_4K};
use zerocopy::AsBytes;

use crate::firmware::Firmware;
use crate::igvm_params::{IgvmGuestContext, IgvmParamBlockFwInfo};

#[derive(Default)]
pub struct IgvmFirmware {
    num_param_index: u32,
    directives: Vec<IgvmDirectiveHeader>,
    fw_info: IgvmParamBlockFwInfo,
    start_rip: Option<u64>,
    guest_context: Option<IgvmGuestContext>,
    vtom: u64,
    lowest_gpa: u64,
    highest_gpa: u64,
}

impl IgvmFirmware {
    pub fn new(num_param_index: u32) -> Self {
        Self {
            num_param_index,
            directives: Vec::new(),
            fw_info: IgvmParamBlockFwInfo::default(),
            start_rip: None,
            guest_context: None,
            vtom: 0,
            lowest_gpa: u64::MAX,
            highest_gpa: 0,
        }
    }

    pub fn parse(
        filename: &String,
        parameter_count: u32,
        compatibility_mask: u32,
    ) -> Result<Box<dyn Firmware>, Box<dyn Error>> {
        // Read and parse Hyper-V firmware.
        let mut igvm_fw = IgvmFirmware::new(parameter_count);
        let igvm_buffer = fs::read(filename)?;
        let igvm = IgvmFile::new_from_binary(igvm_buffer.as_bytes(), None)?;

        let directives: Result<Vec<IgvmDirectiveHeader>, Box<dyn Error>> = igvm
            .directives()
            .iter()
            .filter_map(|directive| igvm_fw.translate_directive(directive, compatibility_mask))
            .collect();

        igvm_fw.directives = directives?;

        // The base of the firmware must be above 640K.
        igvm_fw.fw_info.start = igvm_fw.lowest_gpa.try_into()?;
        igvm_fw.fw_info.size = (igvm_fw.highest_gpa - igvm_fw.lowest_gpa).try_into()?;
        igvm_fw.fw_info.in_low_memory = 1;
        if igvm_fw.fw_info.start < 0xA0000 {
            return Err("IGVM firmware base is lower than 640K".into());
        }

        if let Some(guest_context) = &mut igvm_fw.guest_context {
            if let Some(start_rip) = igvm_fw.start_rip {
                guest_context.rip = start_rip;
            } else {
                return Err("IGVM firmware does not contain starting RIP".into());
            }
        } else {
            return Err("IGVM firmware does not contain guest context".into());
        }

        // Mark the range between the top of the stage 2 area and the base
        // of memory as a range that needs to be validated.
        igvm_fw.fw_info.prevalidated_count = 1;
        igvm_fw.fw_info.prevalidated[0].base = 0xA0000;
        igvm_fw.fw_info.prevalidated[0].size = igvm_fw.fw_info.start - 0xA0000;

        Ok(Box::new(igvm_fw))
    }

    fn update_gpa_range(&mut self, gpa_bottom: u64, gpa_top: u64) {
        self.lowest_gpa = self.lowest_gpa.min(gpa_bottom);
        self.highest_gpa = self.highest_gpa.max(gpa_top);
    }

    fn set_guest_context(&mut self, vmsa: &SevVmsa) {
        self.guest_context = Some(IgvmGuestContext {
            cr0: vmsa.cr0,
            cr3: vmsa.cr3,
            cr4: vmsa.cr4,
            efer: vmsa.efer,
            gdt_base: vmsa.gdtr.base,
            gdt_limit: vmsa.gdtr.limit,
            code_selector: vmsa.cs.selector,
            data_selector: vmsa.ds.selector,
            rip: vmsa.rip,
            rax: vmsa.rax,
            rcx: vmsa.rcx,
            rdx: vmsa.rdx,
            rbx: vmsa.rbx,
            rsp: vmsa.rsp,
            rbp: vmsa.rbp,
            rsi: vmsa.rsi,
            rdi: vmsa.rdi,
            r8: vmsa.r8,
            r9: vmsa.r9,
            r10: vmsa.r10,
            r11: vmsa.r11,
            r12: vmsa.r12,
            r13: vmsa.r13,
            r14: vmsa.r14,
            r15: vmsa.r15,
        });
    }

    fn translate_directive(
        &mut self,
        directive: &IgvmDirectiveHeader,
        compatibility_mask: u32,
    ) -> Option<Result<IgvmDirectiveHeader, Box<dyn Error>>> {
        match directive {
            IgvmDirectiveHeader::ParameterArea {
                number_of_bytes,
                parameter_area_index,
                initial_data,
            } => Some(Ok(IgvmDirectiveHeader::ParameterArea {
                number_of_bytes: *number_of_bytes,
                parameter_area_index: parameter_area_index + self.num_param_index,
                initial_data: initial_data.clone(),
            })),
            IgvmDirectiveHeader::ParameterInsert(mut param) => {
                param.parameter_area_index += self.num_param_index;
                self.update_gpa_range(param.gpa, param.gpa + PAGE_SIZE_4K);
                Some(Ok(IgvmDirectiveHeader::ParameterInsert(param)))
            }
            IgvmDirectiveHeader::VpCount(mut param) => {
                param.parameter_area_index += self.num_param_index;
                Some(Ok(IgvmDirectiveHeader::VpCount(param)))
            }
            IgvmDirectiveHeader::MemoryMap(mut param) => {
                param.parameter_area_index += self.num_param_index;
                Some(Ok(IgvmDirectiveHeader::MemoryMap(param)))
            }
            IgvmDirectiveHeader::EnvironmentInfo(mut param) => {
                param.parameter_area_index += self.num_param_index;
                Some(Ok(IgvmDirectiveHeader::EnvironmentInfo(param)))
            }
            IgvmDirectiveHeader::CommandLine(mut param) => {
                param.parameter_area_index += self.num_param_index;
                Some(Ok(IgvmDirectiveHeader::CommandLine(param)))
            }
            IgvmDirectiveHeader::Madt(mut param) => {
                param.parameter_area_index += self.num_param_index;
                Some(Ok(IgvmDirectiveHeader::Madt(param)))
            }
            IgvmDirectiveHeader::Srat(mut param) => {
                param.parameter_area_index += self.num_param_index;
                Some(Ok(IgvmDirectiveHeader::Srat(param)))
            }
            IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask: page_compatibility_mask,
                flags,
                data_type,
                data,
            } => {
                if (page_compatibility_mask & compatibility_mask) != 0 {
                    if *gpa == 0 && !data.is_empty() {
                        // The page at zero is special: it includes logic to PVALIDATE
                        // the first 1 MB of memory.  That should be skipped when
                        // running under an SVSM because that memory is validated by
                        // the SVSM itself.  In this case, the page is read to extract
                        // the true starting RIP, but the page data itself is not
                        // inserted into the final IGVM file.
                        if data.len() >= 8 {
                            let rip_buf: [u8; 8] = data[..8].try_into().unwrap();
                            self.start_rip = Some(u64::from_le_bytes(rip_buf));
                        }
                        None
                    } else if (*data_type == IgvmPageDataType::NORMAL)
                        || (*data_type == IgvmPageDataType::CPUID_DATA)
                        || (*data_type == IgvmPageDataType::CPUID_XF)
                    {
                        self.update_gpa_range(*gpa, *gpa + PAGE_SIZE_4K);
                        // CPUID pages can be manifested directly in the firmware
                        // address space; they do not have to be pre-processed by
                        // the SVSM.
                        Some(Ok(IgvmDirectiveHeader::PageData {
                            gpa: *gpa,
                            compatibility_mask,
                            flags: *flags,
                            data_type: *data_type,
                            data: data.clone(),
                        }))
                    } else if *data_type == IgvmPageDataType::SECRETS {
                        // The secrets page is not manifested in the final file.
                        // Instead, simply capture the location of the secrets
                        // page so it can be copied into the correct location by
                        // the SVSM.
                        self.update_gpa_range(*gpa, *gpa + PAGE_SIZE_4K);
                        let secrets_page = u32::try_from(*gpa);
                        // The Hyper-V firmware reserves the page following the
                        // secrets page for the calling area.
                        let caa_page = u32::try_from(*gpa + PAGE_SIZE_4K);
                        if secrets_page.is_err() {
                            return Some(Err(secrets_page.err().unwrap().into()));
                        }
                        if caa_page.is_err() {
                            return Some(Err(caa_page.err().unwrap().into()));
                        }
                        self.fw_info.secrets_page = secrets_page.unwrap();
                        self.fw_info.caa_page = caa_page.unwrap();
                        None
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            IgvmDirectiveHeader::SnpVpContext {
                gpa: _,
                compatibility_mask: vp_compatibility_mask,
                vp_index,
                vmsa,
            } => {
                if (vp_compatibility_mask & compatibility_mask) != 0 {
                    if *vp_index != 0 {
                        return Some(Err(
                            "IGVM firmware file contains VP context for VP with index > 0".into(),
                        ));
                    }
                    self.set_guest_context(vmsa);
                    if vmsa.sev_features.vtom() {
                        self.vtom = vmsa.virtual_tom;
                    }
                }
                None
            }
            IgvmDirectiveHeader::RequiredMemory {
                gpa: _,
                compatibility_mask: _,
                number_of_bytes: _,
                vtl2_protectable: _,
            } => {
                // This can be ignored when importing firmware files.
                None
            }
            _ => Some(Err(
                "IGVM firmware file contains unsupported directives".into()
            )),
        }
    }
}

impl Firmware for IgvmFirmware {
    fn directives(&self) -> &Vec<IgvmDirectiveHeader> {
        &self.directives
    }

    fn get_guest_context(&self) -> Option<IgvmGuestContext> {
        self.guest_context
    }

    fn get_vtom(&self) -> u64 {
        self.vtom
    }

    fn get_fw_info(&self) -> IgvmParamBlockFwInfo {
        self.fw_info
    }
}
