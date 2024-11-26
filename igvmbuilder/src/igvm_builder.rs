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

use bootlib::igvm_params::{
    IgvmGuestContext, IgvmParamBlock, IgvmParamBlockFwInfo, IgvmParamBlockFwMem,
};
use bootlib::platform::SvsmPlatformType;
use clap::Parser;
use igvm::{
    Arch, IgvmDirectiveHeader, IgvmFile, IgvmInitializationHeader, IgvmPlatformHeader, IgvmRevision,
};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_VHS_PARAMETER,
    IGVM_VHS_PARAMETER_INSERT, IGVM_VHS_SUPPORTED_PLATFORM, PAGE_SIZE_4K,
};
use zerocopy::AsBytes;

use crate::cmd_options::{CmdOptions, Hypervisor};
use crate::cpuid::SnpCpuidPage;
use crate::firmware::{parse_firmware, Firmware};
use crate::platform::PlatformMask;
use crate::stage2_stack::Stage2Stack;
use crate::vmsa::{construct_start_context, construct_vmsa};
use crate::GpaMap;

pub const SNP_COMPATIBILITY_MASK: u32 = 1;
pub const NATIVE_COMPATIBILITY_MASK: u32 = 2;
pub static COMPATIBILITY_MASK: PlatformMask = PlatformMask::new();

// Parameter area indices
const IGVM_GENERAL_PARAMS_PA: u32 = 0;
const IGVM_MEMORY_MAP_PA: u32 = 1;
const IGVM_PARAMETER_COUNT: u32 = 2;

const _: () = assert!(size_of::<IgvmParamBlock>() as u64 <= PAGE_SIZE_4K);
const _: () = assert!(size_of::<IgvmGuestContext>() as u64 <= PAGE_SIZE_4K);

pub struct IgvmBuilder {
    options: CmdOptions,
    use_igvm_v2: bool,
    firmware: Option<Box<dyn Firmware>>,
    gpa_map: GpaMap,
    platforms: Vec<IgvmPlatformHeader>,
    initialization: Vec<IgvmInitializationHeader>,
    directives: Vec<IgvmDirectiveHeader>,
}

impl IgvmBuilder {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let options = CmdOptions::parse();

        // Assume revision 1 unless some option requires the use of a different
        // revision.
        let mut use_igvm_v2 = false;

        // SNP is always included in the compatibility mask regardless of the
        // provided options.
        COMPATIBILITY_MASK.add(SNP_COMPATIBILITY_MASK);

        // Include the NATIVE platform if requested.
        if options.native {
            COMPATIBILITY_MASK.add(NATIVE_COMPATIBILITY_MASK);
            use_igvm_v2 = true;
        }

        let firmware = match options.firmware {
            Some(_) => Some(parse_firmware(
                &options,
                IGVM_PARAMETER_COUNT,
                COMPATIBILITY_MASK.get(),
            )?),
            None => None,
        };
        let gpa_map = GpaMap::new(&options, &firmware)?;
        Ok(Self {
            options,
            firmware,
            gpa_map,
            platforms: vec![],
            initialization: vec![],
            directives: vec![],
            use_igvm_v2,
        })
    }

    fn compare_pages(
        directive_a: &IgvmDirectiveHeader,
        directive_b: &IgvmDirectiveHeader,
    ) -> Ordering {
        let a = match directive_a {
            IgvmDirectiveHeader::PageData { gpa, .. }
            | IgvmDirectiveHeader::SnpVpContext { gpa, .. } => gpa,
            _ => panic!("Attempted to compare non-page/vp directive"),
        };
        let b = match directive_b {
            IgvmDirectiveHeader::PageData { gpa, .. }
            | IgvmDirectiveHeader::SnpVpContext { gpa, .. } => gpa,
            _ => panic!("Attempted to compare non-page/vp directive"),
        };
        a.cmp(b)
    }

    pub fn build(mut self) -> Result<(), Box<dyn Error>> {
        let param_block = self.create_param_block()?;
        self.build_directives(&param_block)?;
        self.build_initialization()?;
        self.build_platforms(&param_block);

        // Separate the directive pages out from the others so we can populate them last.
        let (mut pages, others): (Vec<_>, Vec<_>) = self
            .directives
            .iter()
            .cloned()
            .partition(Self::filter_pages);

        if self.options.sort {
            pages.sort_by(Self::compare_pages);
        }
        self.directives = others;
        self.directives.append(&mut pages);

        if self.options.verbose {
            println!("{param_block:#X?}");
        }

        let igvm_revision = if self.use_igvm_v2 {
            IgvmRevision::V2 {
                arch: Arch::X64,
                page_size: PAGE_SIZE_4K.try_into().unwrap(),
            }
        } else {
            IgvmRevision::V1
        };

        let file = IgvmFile::new(
            igvm_revision,
            self.platforms,
            self.initialization,
            self.directives,
        )
        .map_err(|e| {
            eprintln!("Failed to create output file");
            e
        })?;

        let mut binary_file = Vec::new();
        file.serialize(&mut binary_file)?;

        let mut output = File::create(&self.options.output).map_err(|e| {
            eprintln!("Failed to create output file {}", self.options.output);
            e
        })?;
        output.write_all(binary_file.as_slice()).map_err(|e| {
            eprintln!("Failed to write output file {}", self.options.output);
            e
        })?;
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
                secrets_page: 0,
                caa_page: 0,
                cpuid_page: 0,
                prevalidated_count: 0,
                prevalidated: [IgvmParamBlockFwMem { base: 0, size: 0 }; 8],
                ..Default::default()
            };
            let vtom = match self.options.hypervisor {
                Hypervisor::Qemu => 0,
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
            firmware: fw_info,
            kernel_reserved_size: PAGE_SIZE_4K as u32, // Reserved for VMSA
            kernel_size: self.gpa_map.kernel.get_size() as u32,
            kernel_base: self.gpa_map.kernel.get_start(),
            vtom,
            ..Default::default()
        };

        // Calculate the kernel size and base.
        match self.options.hypervisor {
            Hypervisor::Qemu => {
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
        if COMPATIBILITY_MASK.contains(SNP_COMPATIBILITY_MASK) {
            self.platforms.push(IgvmPlatformHeader::SupportedPlatform(
                IGVM_VHS_SUPPORTED_PLATFORM {
                    compatibility_mask: SNP_COMPATIBILITY_MASK,
                    highest_vtl: 2,
                    platform_type: IgvmPlatformType::SEV_SNP,
                    platform_version: 1,
                    shared_gpa_boundary: param_block.vtom,
                },
            ));
        }
        if COMPATIBILITY_MASK.contains(NATIVE_COMPATIBILITY_MASK) {
            self.platforms.push(IgvmPlatformHeader::SupportedPlatform(
                IGVM_VHS_SUPPORTED_PLATFORM {
                    compatibility_mask: NATIVE_COMPATIBILITY_MASK,
                    highest_vtl: 2,
                    platform_type: IgvmPlatformType::NATIVE,
                    platform_version: 1,
                    shared_gpa_boundary: 0,
                },
            ));
        }
    }

    fn build_initialization(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(policy) = &self.options.policy {
            let policy = u64::from_str_radix(policy.trim_start_matches("0x"), 16)?;
            self.initialization
                .push(IgvmInitializationHeader::GuestPolicy {
                    policy,
                    compatibility_mask: COMPATIBILITY_MASK.get(),
                })
        }
        Ok(())
    }

    fn build_directives(&mut self, param_block: &IgvmParamBlock) -> Result<(), Box<dyn Error>> {
        // Populate firmware directives.
        if let Some(firmware) = &self.firmware {
            self.directives.extend_from_slice(firmware.directives());
            // If the firmware has a guest context then add it.
            if let Some(guest_context) = firmware.get_guest_context() {
                self.add_guest_context(&guest_context);
            }
        }

        // Describe the kernel RAM region
        self.directives.push(IgvmDirectiveHeader::RequiredMemory {
            gpa: param_block.kernel_base,
            compatibility_mask: COMPATIBILITY_MASK.get(),
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
                compatibility_mask: COMPATIBILITY_MASK.get(),
                parameter_area_index: IGVM_MEMORY_MAP_PA,
            },
        ));
        self.directives.push(IgvmDirectiveHeader::ParameterInsert(
            IGVM_VHS_PARAMETER_INSERT {
                gpa: self.gpa_map.general_params.get_start(),
                compatibility_mask: COMPATIBILITY_MASK.get(),
                parameter_area_index: IGVM_GENERAL_PARAMS_PA,
            },
        ));

        // Construct a native context object to capture the start context.
        let start_context = construct_start_context();

        if COMPATIBILITY_MASK.contains(SNP_COMPATIBILITY_MASK) {
            // Add the VMSA.
            self.directives.push(construct_vmsa(
                start_context.as_ref(),
                self.gpa_map.vmsa.get_start(),
                param_block.vtom,
                SNP_COMPATIBILITY_MASK,
                &self.options.sev_features,
            ));
        }

        if COMPATIBILITY_MASK.contains(NATIVE_COMPATIBILITY_MASK) {
            // Include the native start context.
            self.directives
                .push(IgvmDirectiveHeader::X64NativeVpContext {
                    compatibility_mask: NATIVE_COMPATIBILITY_MASK,
                    context: start_context,
                    vp_index: 0,
                });
        }

        // Add the IGVM parameter block
        self.add_param_block(param_block);

        // Add optional filesystem image
        if let Some(fs) = &self.options.filesystem {
            self.add_data_pages_from_file(&fs.clone(), self.gpa_map.kernel_fs.get_start())?;
        }

        // Add the kernel elf binary
        self.add_data_pages_from_file(
            &self.options.kernel.clone(),
            self.gpa_map.kernel_elf.get_start(),
        )?;

        if COMPATIBILITY_MASK.contains(SNP_COMPATIBILITY_MASK) {
            // CPUID page
            let cpuid_page = SnpCpuidPage::new()?;
            cpuid_page.add_directive(
                self.gpa_map.cpuid_page.get_start(),
                COMPATIBILITY_MASK.get(),
                &mut self.directives,
            );

            // Secrets page
            self.add_empty_pages(
                self.gpa_map.secrets_page.get_start(),
                self.gpa_map.secrets_page.get_size(),
                IgvmPageDataType::SECRETS,
            )?;
        }

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

        // Populate the stage 2 stack.  This has different contents on each
        // platform.
        let stage2_stack = Stage2Stack::new(&self.gpa_map, param_block.vtom);
        if COMPATIBILITY_MASK.contains(SNP_COMPATIBILITY_MASK) {
            stage2_stack.add_directive(
                self.gpa_map.stage2_stack.get_start(),
                SvsmPlatformType::Snp,
                &mut self.directives,
            );
        }
        if COMPATIBILITY_MASK.contains(NATIVE_COMPATIBILITY_MASK) {
            stage2_stack.add_directive(
                self.gpa_map.stage2_stack.get_start(),
                SvsmPlatformType::Native,
                &mut self.directives,
            );
        }

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
        let mut in_file = File::open(path).map_err(|e| {
            eprintln!("Could not open input file {}", path);
            e
        })?;
        let mut buf = vec![0; 4096];

        while let Ok(len) = in_file.read(&mut buf) {
            if len == 0 {
                break;
            }
            self.directives
                .push(Self::new_page_data(gpa, COMPATIBILITY_MASK.get(), buf));
            gpa += PAGE_SIZE_4K;
            buf = vec![0; 4096];
        }
        Ok(())
    }

    fn add_param_block(&mut self, param_block: &IgvmParamBlock) {
        let mut data = param_block.as_bytes().to_vec();
        data.resize(PAGE_SIZE_4K as usize, 0);

        self.directives.push(IgvmDirectiveHeader::PageData {
            gpa: self.gpa_map.igvm_param_block.get_start(),
            compatibility_mask: COMPATIBILITY_MASK.get(),
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data,
        });
    }

    fn add_guest_context(&mut self, guest_context: &IgvmGuestContext) {
        let mut data = guest_context.as_bytes().to_vec();
        data.resize(PAGE_SIZE_4K as usize, 0);

        self.directives.push(IgvmDirectiveHeader::PageData {
            gpa: self.gpa_map.guest_context.get_start(),
            compatibility_mask: COMPATIBILITY_MASK.get(),
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data,
        });
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
                compatibility_mask: COMPATIBILITY_MASK.get(),
                flags: IgvmPageDataFlags::new(),
                data_type,
                data: vec![],
            });
        }
        Ok(())
    }

    fn filter_pages(directive: &IgvmDirectiveHeader) -> bool {
        matches!(directive, IgvmDirectiveHeader::PageData { .. })
            || matches!(directive, IgvmDirectiveHeader::SnpVpContext { .. })
    }
}
