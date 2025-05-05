// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;

use bootlib::igvm_params::{IgvmGuestContext, IgvmParamBlockFwInfo};
use bootlib::kernel_launch::{LOWMEM_END, STAGE2_HEAP_END};
use igvm::snp_defs::SevVmsa;
use igvm::{IgvmDirectiveHeader, IgvmFile};
use igvm_defs::{
    IgvmPageDataType, IgvmVariableHeaderType, IGVM_VHS_PARAMETER, IGVM_VHS_PARAMETER_INSERT,
    PAGE_SIZE_4K,
};
use zerocopy::IntoBytes;

use crate::firmware::Firmware;

struct IgvmParameter {
    pub parameter_type: IgvmVariableHeaderType,
    pub offset: u32,
}

#[derive(Default)]
struct IgvmParameterArea {
    pub number_of_bytes: u64,
    pub parameter_list: Vec<IgvmParameter>,
    pub memory_map: bool,
    pub gpa: Option<u64>,
}

#[derive(Default)]
pub struct IgvmFirmware {
    directives: Vec<IgvmDirectiveHeader>,
    fw_info: IgvmParamBlockFwInfo,
    start_rip: Option<u64>,
    guest_context: Option<IgvmGuestContext>,
    vtom: u64,
    lowest_gpa: u64,
    highest_gpa: u64,
}

impl IgvmFirmware {
    pub fn new() -> Self {
        Self {
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
        let mut igvm_fw = IgvmFirmware::new();
        let igvm_buffer = fs::read(filename).inspect_err(|_| {
            eprintln!("Failed to open firmware file {}", filename);
        })?;
        let igvm = IgvmFile::new_from_binary(igvm_buffer.as_bytes(), None)?;
        let mut parameters = IgvmParameterList::new();

        let directives: Result<Vec<IgvmDirectiveHeader>, Box<dyn Error>> = igvm
            .directives()
            .iter()
            .filter_map(|directive| {
                igvm_fw.translate_directive(directive, compatibility_mask, &mut parameters)
            })
            .collect();

        igvm_fw.directives = directives?;

        // Add all of the parameters that were captured.  For each one that
        // results in new directives, the parameter index is incremented.
        let mut parameter_index = parameter_count;
        for parameter in parameters.parameters.values() {
            if igvm_fw.add_parameter_directives(parameter_index, parameter, compatibility_mask)? {
                parameter_index += 1;
            }
        }

        // The base of the firmware must be above 640K.
        igvm_fw.fw_info.start = igvm_fw.lowest_gpa.try_into()?;
        igvm_fw.fw_info.size = (igvm_fw.highest_gpa - igvm_fw.lowest_gpa).try_into()?;
        igvm_fw.fw_info.in_low_memory = 1;
        if igvm_fw.fw_info.start < LOWMEM_END {
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

        // Mark the range between the top of the stage 2 heap and the base
        // of memory as a range that needs to be validated.
        igvm_fw.fw_info.prevalidated_count = 1;
        igvm_fw.fw_info.prevalidated[0].base = STAGE2_HEAP_END;
        igvm_fw.fw_info.prevalidated[0].size = igvm_fw.fw_info.start - STAGE2_HEAP_END;

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
        parameters: &mut IgvmParameterList,
    ) -> Option<Result<IgvmDirectiveHeader, Box<dyn Error>>> {
        // When processing directives, parameter information is excluded from
        // the list of directives that are passed through.  Instead, all
        // parameter information is collected into a separate structure so that
        // parameter information can be regenerated based on the parameter
        // information that was actually seen.
        match directive {
            IgvmDirectiveHeader::ParameterArea {
                number_of_bytes,
                parameter_area_index,
                ..
            } => {
                // When establishing a parameter area, the initial data is
                // ignored, since it is not used for IGVM-based firmware.
                if let Err(e) = parameters.parameter_area(number_of_bytes, parameter_area_index) {
                    Some(Err(e))
                } else {
                    None
                }
            }
            IgvmDirectiveHeader::ParameterInsert(param) => {
                if (param.compatibility_mask & compatibility_mask) == 0 {
                    None
                } else if let Err(e) = parameters.parameter_insert(param) {
                    Some(Err(e))
                } else {
                    None
                }
            }
            IgvmDirectiveHeader::VpCount(p) => {
                parameters.parameter_type(IgvmVariableHeaderType::IGVM_VHT_VP_COUNT_PARAMETER, p)
            }
            IgvmDirectiveHeader::MemoryMap(p) => {
                // Identify the memory map as a special parameter type.
                if let Err(e) = parameters.memory_map_parameter(p) {
                    Some(Err(e))
                } else {
                    None
                }
            }
            IgvmDirectiveHeader::EnvironmentInfo(p) => parameters.parameter_type(
                IgvmVariableHeaderType::IGVM_VHT_ENVIRONMENT_INFO_PARAMETER,
                p,
            ),
            IgvmDirectiveHeader::CommandLine(p) => {
                parameters.parameter_type(IgvmVariableHeaderType::IGVM_VHT_COMMAND_LINE, p)
            }
            IgvmDirectiveHeader::Madt(p) => {
                parameters.parameter_type(IgvmVariableHeaderType::IGVM_VHT_MADT, p)
            }
            IgvmDirectiveHeader::Srat(p) => {
                parameters.parameter_type(IgvmVariableHeaderType::IGVM_VHT_SRAT, p)
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
                        let secrets_page = match u32::try_from(*gpa) {
                            Ok(val) => val,
                            Err(e) => return Some(Err(e.into())),
                        };
                        // The Hyper-V firmware reserves the page following the
                        // secrets page for the calling area.
                        let caa_page = match u32::try_from(*gpa + PAGE_SIZE_4K) {
                            Ok(val) => val,
                            Err(e) => return Some(Err(e.into())),
                        };
                        self.fw_info.secrets_page = secrets_page;
                        self.fw_info.caa_page = caa_page;
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
            // This can be ignored when importing firmware files.
            IgvmDirectiveHeader::RequiredMemory { .. } => None,
            _ => Some(Err(
                "IGVM firmware file contains unsupported directives".into()
            )),
        }
    }

    fn add_parameter_directives(
        &mut self,
        parameter_index: u32,
        parameter_area: &IgvmParameterArea,
        compatibility_mask: u32,
    ) -> Result<bool, Box<dyn Error>> {
        // Ignore parameter areas that were never populated or which have no
        // assigned GPA.
        if let Some(gpa) = parameter_area.gpa {
            if parameter_area.memory_map {
                // Capture the memory map in the firmware information.
                let memory_map_page = gpa / PAGE_SIZE_4K;
                self.fw_info.memory_map_page = memory_map_page as u32;
                if self.fw_info.memory_map_page as u64 != memory_map_page {
                    let e = format!("Memory map address {:#018x} is larger than 32 bits", gpa);
                    return Err(e.into());
                }
                let page_count = parameter_area.number_of_bytes.div_ceil(PAGE_SIZE_4K);
                // Truncate the page count if it is too large to fit into a
                // 32-bit number.  It is acceptable for the SVSM to provide a
                // smaller set of data than the firmware is capable of
                // handling.
                self.fw_info.memory_map_page_count = if page_count > 0xFFFF_FFFF {
                    0xFFFF_FFFF
                } else {
                    page_count as u32
                };

                Ok(false)
            } else if parameter_area.parameter_list.is_empty() {
                Ok(false)
            } else {
                // Insert a parameter area directive to describe this parameter
                // area, using a new index value.
                self.directives.push(IgvmDirectiveHeader::ParameterArea {
                    number_of_bytes: parameter_area.number_of_bytes,
                    parameter_area_index: parameter_index,
                    initial_data: Vec::new(),
                });

                // Insert a parameter directive for each parameter associated
                // with this parameter area.
                for parameter_value in &parameter_area.parameter_list {
                    let p = IGVM_VHS_PARAMETER {
                        parameter_area_index: parameter_index,
                        byte_offset: parameter_value.offset,
                    };
                    let parameter_directive = match parameter_value.parameter_type {
                        IgvmVariableHeaderType::IGVM_VHT_VP_COUNT_PARAMETER => {
                            IgvmDirectiveHeader::VpCount(p)
                        }

                        IgvmVariableHeaderType::IGVM_VHT_ENVIRONMENT_INFO_PARAMETER => {
                            IgvmDirectiveHeader::EnvironmentInfo(p)
                        }

                        IgvmVariableHeaderType::IGVM_VHT_COMMAND_LINE => {
                            IgvmDirectiveHeader::CommandLine(p)
                        }
                        IgvmVariableHeaderType::IGVM_VHT_MADT => IgvmDirectiveHeader::Madt(p),
                        IgvmVariableHeaderType::IGVM_VHT_SRAT => IgvmDirectiveHeader::Srat(p),
                        _ => {
                            panic!(
                                "Missing complete handling for parameter type {}",
                                parameter_value.parameter_type.0
                            );
                        }
                    };

                    self.directives.push(parameter_directive);
                }

                // Insert a directive to insert this parameter area into the
                // address space.
                self.directives.push(IgvmDirectiveHeader::ParameterInsert(
                    IGVM_VHS_PARAMETER_INSERT {
                        gpa,
                        compatibility_mask,
                        parameter_area_index: parameter_index,
                    },
                ));

                // Since this parameter area was used, indicate that the
                // parameter index must be incremented.
                Ok(true)
            }
        } else {
            Ok(false)
        }
    }
}

struct IgvmParameterList {
    pub parameters: BTreeMap<u32, IgvmParameterArea>,
}

impl IgvmParameterList {
    fn new() -> Self {
        Self {
            parameters: BTreeMap::new(),
        }
    }

    pub fn parameter_area(
        &mut self,
        number_of_bytes: &u64,
        parameter_area_index: &u32,
    ) -> Result<(), Box<dyn Error>> {
        // Construct an empty parameter area.  The initial data is unused.
        let parameter = IgvmParameterArea {
            number_of_bytes: *number_of_bytes,
            memory_map: false,
            parameter_list: Vec::new(),
            gpa: None,
        };

        if self
            .parameters
            .insert(*parameter_area_index, parameter)
            .is_some()
        {
            // This parameter area index must not already be present in the
            // tree.
            let e = format!(
                "Parameter area {} exists more than once",
                *parameter_area_index
            );
            Err(e.into())
        } else {
            Ok(())
        }
    }

    pub fn parameter_type(
        &mut self,
        parameter_type: IgvmVariableHeaderType,
        parameter: &IGVM_VHS_PARAMETER,
    ) -> Option<Result<IgvmDirectiveHeader, Box<dyn Error>>> {
        // Bind this parameter to the corresponding parameter area.  Multiple
        // parameters can exist within a single parameter area.
        if let Some(parameter_area) = self.parameters.get_mut(&parameter.parameter_area_index) {
            if parameter_area.memory_map {
                Some(Err(
                    "Memory map inhabits a parameter area with other parameters".into(),
                ))
            } else {
                parameter_area.parameter_list.push(IgvmParameter {
                    parameter_type,
                    offset: parameter.byte_offset,
                });
                None
            }
        } else {
            let e = format!(
                "Parameter {} for non-existent area {}",
                parameter_type.0, parameter.parameter_area_index
            );
            Some(Err(e.into()))
        }
    }

    fn memory_map_parameter(
        &mut self,
        parameter: &IGVM_VHS_PARAMETER,
    ) -> Result<(), Box<dyn Error>> {
        if parameter.byte_offset != 0 {
            Err("Memory map parameter specified with non-zero offset".into())
        } else if let Some(parameter_area) =
            self.parameters.get_mut(&parameter.parameter_area_index)
        {
            // The memory map cannot inhabit the same parameter area as any
            // other parameter.
            if !parameter_area.parameter_list.is_empty() || parameter_area.memory_map {
                Err("Memory map inhabits a parameter area with other parameters".into())
            } else {
                parameter_area.memory_map = true;
                Ok(())
            }
        } else {
            let e = format!(
                "Memory map parameter for non-existent area {}",
                parameter.parameter_area_index
            );
            Err(e.into())
        }
    }

    pub fn parameter_insert(
        &mut self,
        parameter: &IGVM_VHS_PARAMETER_INSERT,
    ) -> Result<(), Box<dyn Error>> {
        // Capture the GPA information for the parameter area.  The
        // compatibility mask is ignored, since any supplied firmware file is
        // assumed to be compatible with all platform types supported by the
        // IGVM file being constructed.
        if let Some(parameter_area) = self.parameters.get_mut(&parameter.parameter_area_index) {
            parameter_area.gpa = Some(parameter.gpa);
            Ok(())
        } else {
            let e = format!(
                "Parameter insert for non-existent area {}",
                parameter.parameter_area_index
            );
            Err(e.into())
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
