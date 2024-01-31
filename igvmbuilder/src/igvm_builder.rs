// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::cmp::Ordering;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;

use clap::Parser;
use igvm::{IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader, IgvmRevision};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_VHS_PARAMETER,
    IGVM_VHS_PARAMETER_INSERT, IGVM_VHS_SUPPORTED_PLATFORM, PAGE_SIZE_4K,
};

use crate::cmd_options::{CmdOptions, Hypervisor};
use crate::cpuid::SnpCpuidPage;
use crate::firmware::{parse_firmware, Firmware};
use crate::igvm_params::{
    IgvmGuestContext, IgvmParamBlock, IgvmParamBlockFwInfo, IgvmParamBlockFwMem,
};
use crate::stage2_stack::Stage2Stack;
use crate::vmsa::construct_vmsa;
use crate::GpaMap;

const COMPATIBILITY_MASK: u32 = 1;

// Parameter area indices
const IGVM_GENERAL_PARAMS_PA: u32 = 0;
const IGVM_MEMORY_MAP_PA: u32 = 1;
const IGVM_PARAMETER_COUNT: u32 = 2;

pub struct IgvmBuilder {
    options: CmdOptions,
    firmware: Option<Box<dyn Firmware>>,
    gpa_map: GpaMap,
    platforms: Vec<IgvmPlatformHeader>,
    directives: Vec<IgvmDirectiveHeader>,
}

impl IgvmBuilder {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let options = CmdOptions::parse();
        let firmware = match options.firmware {
            Some(_) => Some(parse_firmware(
                &options,
                IGVM_PARAMETER_COUNT,
                COMPATIBILITY_MASK,
            )?),
            None => None,
        };
        let gpa_map = GpaMap::new(&options, &firmware)?;
        Ok(Self {
            options,
            firmware,
            gpa_map,
            platforms: vec![],
            directives: vec![],
        })
    }

    fn compare_pages(
        directive_a: &IgvmDirectiveHeader,
        directive_b: &IgvmDirectiveHeader,
    ) -> Ordering {
        let a = match directive_a {
            IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask: _,
                flags: _,
                data_type: _,
                data: _,
            } => gpa,
            _ => panic!("Attempted to compare non-page directive"),
        };
        let b = match directive_b {
            IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask: _,
                flags: _,
                data_type: _,
                data: _,
            } => gpa,
            _ => panic!("Attempted to compare non-page directive"),
        };
        a.cmp(b)
    }

    pub fn build(mut self) -> Result<(), Box<dyn Error>> {
        let param_block = self.create_param_block()?;
        self.build_directives(&param_block)?;
        self.build_platforms(&param_block);

        // Separate the directive pages out from the others so we can populate them last.
        let others: Vec<IgvmDirectiveHeader> = self
            .directives
            .iter()
            .filter(|directive| Self::filter_pages(directive, false))
            .cloned()
            .collect();
        let mut pages: Vec<IgvmDirectiveHeader> = self
            .directives
            .iter()
            .filter(|directive| Self::filter_pages(directive, true))
            .cloned()
            .collect();

        if self.options.sort {
            pages.sort_by(Self::compare_pages);
        }
        self.directives = others;
        self.directives.append(&mut pages);

        if self.options.verbose {
            println!("{param_block:#X?}");
        }

        let file = IgvmFile::new(IgvmRevision::V1, self.platforms, vec![], self.directives)
            .expect("Failed to create output file");

        let mut binary_file = Vec::new();
        file.serialize(&mut binary_file).unwrap();

        let mut output = File::create(&self.options.output)?;
        output.write_all(binary_file.as_slice())?;
        Ok(())
    }

    fn create_param_block(&self) -> Result<IgvmParamBlock, Box<dyn Error>> {
        let param_page_offset = PAGE_SIZE_4K as u32;
        let memory_map_offset = param_page_offset + PAGE_SIZE_4K as u32;
        let (guest_context_offset, param_area_size) = if self.gpa_map.guest_context.get_size() == 0
        {
            (0, memory_map_offset + PAGE_SIZE_4K as u32)
        } else {
            (
                memory_map_offset + PAGE_SIZE_4K as u32,
                memory_map_offset
                    + PAGE_SIZE_4K as u32
                    + self.gpa_map.guest_context.get_size() as u32,
            )
        };

        // Populate the firmware metadata.
        let (fw_info, vtom) = if let Some(firmware) = &self.firmware {
            (firmware.get_fw_info(), firmware.get_vtom())
        } else {
            let fw_info = IgvmParamBlockFwInfo {
                start: 0,
                size: 0,
                in_low_memory: 0,
                _reserved: [0u8; 7],
                secrets_page: 0,
                caa_page: 0,
                cpuid_page: 0,
                prevalidated_count: 0,
                prevalidated: [IgvmParamBlockFwMem { base: 0, size: 0 }; 8],
            };
            let vtom = match self.options.hypervisor {
                Hypervisor::QEMU => 0,
                Hypervisor::HyperV => {
                    // Set the shared GPA boundary at bit 46, below the lowest possible
                    // C-bit position.
                    0x0000400000000000
                }
            };
            (fw_info, vtom)
        };

        // Most of the parameter block can be initialised with constants.
        let mut param_block = IgvmParamBlock {
            param_area_size,
            param_page_offset,
            memory_map_offset,
            guest_context_offset,
            cpuid_page: self.gpa_map.cpuid_page.get_start() as u32,
            secrets_page: self.gpa_map.secrets_page.get_start() as u32,
            debug_serial_port: self.options.get_port_address(),
            _reserved: [0u16; 3],
            firmware: fw_info,
            kernel_reserved_size: PAGE_SIZE_4K as u32, // Reserved for VMSA
            kernel_size: self.gpa_map.kernel.get_size() as u32,
            kernel_base: self.gpa_map.kernel.get_start(),
            vtom,
        };

        // Calculate the kernel size and base.
        match self.options.hypervisor {
            Hypervisor::QEMU => {
                // Place the kernel area at 512 GB with a size of 16 MB.
                param_block.kernel_base = 0x0000008000000000;
                param_block.kernel_size = 0x01000000;
            }
            Hypervisor::HyperV => {
                // Place the kernel area at 64 MB with a size of 16 MB.
                param_block.kernel_base = 0x04000000;
                param_block.kernel_size = 0x01000000;
            }
        }

        Ok(param_block)
    }

    fn build_platforms(&mut self, param_block: &IgvmParamBlock) {
        self.platforms.push(IgvmPlatformHeader::SupportedPlatform(
            IGVM_VHS_SUPPORTED_PLATFORM {
                compatibility_mask: COMPATIBILITY_MASK,
                highest_vtl: 2,
                platform_type: IgvmPlatformType::SEV_SNP,
                platform_version: 1,
                shared_gpa_boundary: param_block.vtom,
            },
        ));
    }

    fn build_directives(&mut self, param_block: &IgvmParamBlock) -> Result<(), Box<dyn Error>> {
        // Populate firmware directives.
        if let Some(firmware) = &self.firmware {
            self.directives.append(&mut firmware.directives().clone());
            // If the firmware has a guest context then add it.
            if let Some(guest_context) = firmware.get_guest_context() {
                self.add_guest_context(&guest_context)?;
            }
        }

        // Describe the kernel RAM region
        self.directives.push(IgvmDirectiveHeader::RequiredMemory {
            gpa: param_block.kernel_base,
            compatibility_mask: COMPATIBILITY_MASK,
            number_of_bytes: param_block.kernel_size,
            vtl2_protectable: false,
        });

        // Create the two parameter areas for memory map and general parameters.
        self.directives.push(IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: PAGE_SIZE_4K,
            parameter_area_index: IGVM_MEMORY_MAP_PA,
            initial_data: vec![],
        });
        self.directives.push(IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: PAGE_SIZE_4K,
            parameter_area_index: IGVM_GENERAL_PARAMS_PA,
            initial_data: vec![],
        });
        self.directives
            .push(IgvmDirectiveHeader::VpCount(IGVM_VHS_PARAMETER {
                parameter_area_index: IGVM_GENERAL_PARAMS_PA,
                byte_offset: 0,
            }));
        self.directives
            .push(IgvmDirectiveHeader::EnvironmentInfo(IGVM_VHS_PARAMETER {
                parameter_area_index: IGVM_GENERAL_PARAMS_PA,
                byte_offset: 4,
            }));
        self.directives
            .push(IgvmDirectiveHeader::MemoryMap(IGVM_VHS_PARAMETER {
                parameter_area_index: IGVM_MEMORY_MAP_PA,
                byte_offset: 0,
            }));
        self.directives.push(IgvmDirectiveHeader::ParameterInsert(
            IGVM_VHS_PARAMETER_INSERT {
                gpa: self.gpa_map.memory_map.get_start(),
                compatibility_mask: COMPATIBILITY_MASK,
                parameter_area_index: IGVM_MEMORY_MAP_PA,
            },
        ));
        self.directives.push(IgvmDirectiveHeader::ParameterInsert(
            IGVM_VHS_PARAMETER_INSERT {
                gpa: self.gpa_map.general_params.get_start(),
                compatibility_mask: COMPATIBILITY_MASK,
                parameter_area_index: IGVM_GENERAL_PARAMS_PA,
            },
        ));

        // Place the VMSA at the base of the kernel region.
        self.directives.push(construct_vmsa(
            self.gpa_map.vmsa.get_start(),
            COMPATIBILITY_MASK,
        )?);

        // Add the IGVM parameter block
        self.add_param_block(param_block)?;

        // Add the kernel elf binary
        self.add_data_pages_from_file(
            &self.options.kernel.clone(),
            self.gpa_map.kernel_elf.get_start(),
        )?;

        // CPUID page
        let cpuid_page = SnpCpuidPage::new()?;
        cpuid_page.add_directive(
            self.gpa_map.cpuid_page.get_start(),
            COMPATIBILITY_MASK,
            &mut self.directives,
        )?;

        // Secrets page
        self.add_empty_pages(
            self.gpa_map.secrets_page.get_start(),
            self.gpa_map.secrets_page.get_size(),
            IgvmPageDataType::SECRETS,
        )?;

        // Populate the empty region above the stage 2 binary.
        self.add_empty_pages(
            self.gpa_map.stage2_free.get_start(),
            self.gpa_map.stage2_free.get_size(),
            IgvmPageDataType::NORMAL,
        )?;

        // Populate the stage 2 binary.
        self.add_data_pages_from_file(
            &self.options.stage2.clone(),
            self.gpa_map.stage2_image.get_start(),
        )?;

        // Populate the stage 2 stack.
        let stage2_stack = Stage2Stack::new(&self.gpa_map);
        stage2_stack.add_directive(
            self.gpa_map.stage2_stack.get_start(),
            COMPATIBILITY_MASK,
            &mut self.directives,
        )?;

        // Populate the empty region at the bottom of RAM.
        self.add_empty_pages(
            self.gpa_map.low_memory.get_start(),
            self.gpa_map.low_memory.get_size(),
            IgvmPageDataType::NORMAL,
        )?;

        Ok(())
    }

    fn new_page_data(gpa: u64, compatibility_mask: u32, data: Vec<u8>) -> IgvmDirectiveHeader {
        IgvmDirectiveHeader::PageData {
            gpa,
            compatibility_mask,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data,
        }
    }

    fn add_data_pages_from_file(
        &mut self,
        path: &String,
        gpa_start: u64,
    ) -> Result<(), Box<dyn Error>> {
        let mut gpa = gpa_start;
        let mut in_file = File::open(path).expect("Could not open input file");
        let mut buf = vec![0; 4096];

        while let Ok(len) = in_file.read(&mut buf) {
            if len == 0 {
                break;
            }
            self.directives.push(Self::new_page_data(gpa, 1, buf));
            gpa += PAGE_SIZE_4K;
            buf = vec![0; 4096];
        }
        Ok(())
    }

    fn add_param_block(&mut self, param_block: &IgvmParamBlock) -> Result<(), Box<dyn Error>> {
        let param_block_data = unsafe {
            let ptr =
                param_block as *const IgvmParamBlock as *const [u8; size_of::<IgvmParamBlock>()];
            &*ptr
        };
        if param_block_data.len() > PAGE_SIZE_4K as usize {
            return Err("IGVM parameter block size exceeds 4K".into());
        }
        let mut param_block_page = [0u8; PAGE_SIZE_4K as usize];
        param_block_page[..param_block_data.len()].clone_from_slice(param_block_data);

        self.directives.push(IgvmDirectiveHeader::PageData {
            gpa: self.gpa_map.igvm_param_block.get_start(),
            compatibility_mask: COMPATIBILITY_MASK,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: param_block_page.to_vec(),
        });
        Ok(())
    }

    fn add_guest_context(
        &mut self,
        guest_context: &IgvmGuestContext,
    ) -> Result<(), Box<dyn Error>> {
        let guest_context_data = unsafe {
            let ptr = guest_context as *const IgvmGuestContext
                as *const [u8; size_of::<IgvmGuestContext>()];
            &*ptr
        };
        if guest_context_data.len() > PAGE_SIZE_4K as usize {
            return Err("IGVM parameter block size exceeds 4K".into());
        }
        let mut guest_context_page = [0u8; PAGE_SIZE_4K as usize];
        guest_context_page[..guest_context_data.len()].clone_from_slice(guest_context_data);

        self.directives.push(IgvmDirectiveHeader::PageData {
            gpa: self.gpa_map.guest_context.get_start(),
            compatibility_mask: COMPATIBILITY_MASK,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: guest_context_page.to_vec(),
        });
        Ok(())
    }

    fn add_empty_pages(
        &mut self,
        gpa_start: u64,
        size: u64,
        data_type: IgvmPageDataType,
    ) -> Result<(), Box<dyn Error>> {
        for gpa in (gpa_start..(gpa_start + size)).step_by(PAGE_SIZE_4K as usize) {
            self.directives.push(IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask: COMPATIBILITY_MASK,
                flags: IgvmPageDataFlags::new(),
                data_type,
                data: vec![],
            });
        }
        Ok(())
    }

    fn filter_pages(directive: &IgvmDirectiveHeader, is_page: bool) -> bool {
        match directive {
            IgvmDirectiveHeader::PageData {
                gpa: _,
                compatibility_mask: _,
                flags: _,
                data_type: _,
                data: _,
            } => is_page,
            _ => !is_page,
        }
    }
}
