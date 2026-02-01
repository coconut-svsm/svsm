// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use std::cmp::Ordering;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::mem::size_of;

use bootdefs::boot_params::BootParamBlock;
use bootdefs::boot_params::GuestFwInfoBlock;
use bootdefs::boot_params::InitialGuestContext;
use bootdefs::platform::SvsmPlatformType;
use bootimg::BootImageError;
use bootimg::BootImageParams;
use bootimg::prepare_boot_image;
use clap::Parser;
use igvm::registers::X86Register;
use igvm::{
    Arch, IgvmDirectiveHeader, IgvmFile, IgvmInitializationHeader, IgvmPlatformHeader, IgvmRevision,
};
use igvm_defs::{
    IGVM_VHS_PARAMETER, IGVM_VHS_PARAMETER_INSERT, IGVM_VHS_SUPPORTED_PLATFORM, IgvmPageDataFlags,
    IgvmPageDataType, IgvmPlatformType, PAGE_SIZE_4K,
};
use zerocopy::IntoBytes;

use crate::GpaMap;
use crate::boot_params::BootParamType;
use crate::cmd_options::{CmdOptions, Hypervisor};
use crate::context::construct_native_start_context;
use crate::context::construct_stage1_image;
use crate::context::construct_start_context;
use crate::context::construct_vmsa;
use crate::cpuid::SnpCpuidPage;
use crate::firmware::{Firmware, parse_firmware};
use crate::paging::construct_init_page_tables;
use crate::platform::PlatformMask;
use crate::sipi::add_sipi_stub;
use crate::stage2_stack::Stage2Stack;

pub const SNP_COMPATIBILITY_MASK: u32 = 1u32 << 0;
pub const NATIVE_COMPATIBILITY_MASK: u32 = 1u32 << 1;
pub const TDP_COMPATIBILITY_MASK: u32 = 1u32 << 2;
pub const VSM_COMPATIBILITY_MASK: u32 = 1u32 << 4;
pub static COMPATIBILITY_MASK: PlatformMask = PlatformMask::new();

pub const ANY_NATIVE_COMPATIBILITY_MASK: u32 = NATIVE_COMPATIBILITY_MASK | VSM_COMPATIBILITY_MASK;

// Parameter area indices
const IGVM_GENERAL_PARAMS_PA: u32 = 0;
const IGVM_MEMORY_MAP_PA: u32 = 1;
const IGVM_MADT_PA: u32 = 2;
const IGVM_PARAMETER_COUNT: u32 = 3;

const _: () = assert!(size_of::<BootParamBlock>() as u64 <= PAGE_SIZE_4K);
const _: () = assert!(size_of::<InitialGuestContext>() as u64 <= PAGE_SIZE_4K);

pub struct IgvmBuilder {
    options: CmdOptions,
    use_igvm_v2: bool,
    firmware: Option<Box<dyn Firmware>>,
    gpa_map: GpaMap,
    vtom: u64,
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

        // Include the SEV-SNP platform if requested.
        if options.snp {
            COMPATIBILITY_MASK.add(SNP_COMPATIBILITY_MASK);
        }
        // Include the TDP platform if requested.
        if options.tdp {
            COMPATIBILITY_MASK.add(TDP_COMPATIBILITY_MASK);
        }
        // Include the VSM_ISOLATION platform if requested.
        if options.vsm {
            COMPATIBILITY_MASK.add(VSM_COMPATIBILITY_MASK);
        }
        // Include the NATIVE platform if requested.
        if options.native {
            COMPATIBILITY_MASK.add(NATIVE_COMPATIBILITY_MASK);
            use_igvm_v2 = true;
        }

        if COMPATIBILITY_MASK.get() == 0 {
            return Err("No platform specified".into());
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
        let vtom = if let Some(fw) = &firmware {
            fw.get_vtom()
        } else {
            match options.hypervisor {
                Hypervisor::Qemu => 0,
                Hypervisor::HyperV => {
                    // Set the shared GPA boundary at bit 46, below the lowest possible
                    // C-bit position.
                    0x0000400000000000
                }
                Hypervisor::Vanadium => 0,
            }
        };
        Ok(Self {
            options,
            firmware,
            gpa_map,
            vtom,
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

        // Construct a native context object to capture the start context.
        let start_rip = self.gpa_map.stage2_image.get_start();
        let start_rsp = self.gpa_map.stage2_stack.get_end() - size_of::<Stage2Stack>() as u64;
        let start_context = construct_start_context(
            start_rip,
            start_rsp,
            self.gpa_map.init_page_tables.get_start(),
        );

        self.build_directives(&param_block, &start_context)?;
        self.build_initialization()?;
        self.build_platforms();

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
        .inspect_err(|_| {
            eprintln!("Failed to create output file");
        })?;

        let mut binary_file = Vec::new();
        file.serialize(&mut binary_file)?;

        let mut output = File::create(&self.options.output).inspect_err(|_| {
            eprintln!("Failed to create output file {}", self.options.output);
        })?;
        output.write_all(binary_file.as_slice()).inspect_err(|_| {
            eprintln!("Failed to write output file {}", self.options.output);
        })?;
        Ok(())
    }

    fn create_param_block(&self) -> Result<BootParamBlock, Box<dyn Error>> {
        // Populate the firmware metadata.
        let fw_info = if let Some(firmware) = &self.firmware {
            firmware.get_fw_info()
        } else {
            GuestFwInfoBlock::default()
        };

        let suppress_svsm_interrupts_on_snp = match self.options.hypervisor {
            Hypervisor::Qemu | Hypervisor::Vanadium => 1,
            _ => 0,
        };

        let has_qemu_testdev = match self.options.hypervisor {
            Hypervisor::Qemu | Hypervisor::Vanadium => 1,
            _ => 0,
        };

        let has_fw_cfg_port = match self.options.hypervisor {
            Hypervisor::Qemu | Hypervisor::Vanadium => 1,
            _ => 0,
        };

        let has_test_iorequests = match self.options.hypervisor {
            Hypervisor::Qemu => 1,
            _ => 0,
        };

        // Most of the parameter block can be initialised with constants.
        Ok(BootParamBlock {
            param_area_size: self.gpa_map.boot_param_layout.total_size(),
            param_page_offset: self
                .gpa_map
                .boot_param_layout
                .get_param_offset(BootParamType::General),
            memory_map_offset: self
                .gpa_map
                .boot_param_layout
                .get_param_offset(BootParamType::MemoryMap),
            madt_offset: self
                .gpa_map
                .boot_param_layout
                .get_param_offset(BootParamType::Madt),
            madt_size: self
                .gpa_map
                .boot_param_layout
                .get_param_size(BootParamType::Madt),
            guest_context_offset: self
                .gpa_map
                .boot_param_layout
                .get_param_size(BootParamType::GuestContext),
            debug_serial_port: self.options.get_port_address(),
            firmware: fw_info,
            vmsa_in_kernel_range: self.gpa_map.vmsa_in_kernel_range as u8,
            kernel_base: self.gpa_map.kernel.get_start(),
            kernel_min_size: self.gpa_map.kernel_min_size,
            kernel_max_size: self.gpa_map.kernel_max_size,
            use_alternate_injection: u8::from(self.options.alt_injection),
            suppress_svsm_interrupts_on_snp,
            has_qemu_testdev,
            has_fw_cfg_port,
            has_test_iorequests,
        })
    }

    fn build_platforms(&mut self) {
        if COMPATIBILITY_MASK.contains(SNP_COMPATIBILITY_MASK) {
            self.platforms.push(IgvmPlatformHeader::SupportedPlatform(
                IGVM_VHS_SUPPORTED_PLATFORM {
                    compatibility_mask: SNP_COMPATIBILITY_MASK,
                    highest_vtl: 2,
                    platform_type: IgvmPlatformType::SEV_SNP,
                    platform_version: 1,
                    shared_gpa_boundary: self.vtom,
                },
            ));
        }
        if COMPATIBILITY_MASK.contains(TDP_COMPATIBILITY_MASK) {
            self.platforms.push(IgvmPlatformHeader::SupportedPlatform(
                IGVM_VHS_SUPPORTED_PLATFORM {
                    compatibility_mask: TDP_COMPATIBILITY_MASK,
                    highest_vtl: 2,
                    platform_type: IgvmPlatformType::TDX,
                    platform_version: 1,
                    shared_gpa_boundary: 0,
                },
            ));
        }
        if COMPATIBILITY_MASK.contains(VSM_COMPATIBILITY_MASK) {
            self.platforms.push(IgvmPlatformHeader::SupportedPlatform(
                IGVM_VHS_SUPPORTED_PLATFORM {
                    compatibility_mask: VSM_COMPATIBILITY_MASK,
                    highest_vtl: 2,
                    platform_type: IgvmPlatformType::VSM_ISOLATION,
                    platform_version: 1,
                    shared_gpa_boundary: 0,
                },
            ));
        }
        if COMPATIBILITY_MASK.contains(NATIVE_COMPATIBILITY_MASK) {
            self.platforms.push(IgvmPlatformHeader::SupportedPlatform(
                IGVM_VHS_SUPPORTED_PLATFORM {
                    compatibility_mask: NATIVE_COMPATIBILITY_MASK,
                    highest_vtl: 0,
                    platform_type: IgvmPlatformType::NATIVE,
                    platform_version: 1,
                    shared_gpa_boundary: 0,
                },
            ));
        }
    }

    fn build_initialization(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(policy) = &self.options.policy {
            if COMPATIBILITY_MASK.contains(SNP_COMPATIBILITY_MASK) {
                let policy = u64::from_str_radix(policy.trim_start_matches("0x"), 16)?;
                self.initialization
                    .push(IgvmInitializationHeader::GuestPolicy {
                        policy,
                        compatibility_mask: SNP_COMPATIBILITY_MASK,
                    })
            } else {
                return Err("Policy not supported by the specified platform(s)".into());
            }
        }
        Ok(())
    }

    fn build_directives(
        &mut self,
        param_block: &BootParamBlock,
        start_context: &[X86Register],
    ) -> Result<(), Box<dyn Error>> {
        // Populate firmware directives.
        if let Some(firmware) = &self.firmware {
            self.directives.extend_from_slice(firmware.directives());
            // If the firmware has a guest context then add it.
            if let Some(guest_context) = firmware.get_guest_context() {
                self.add_guest_context(&guest_context);
            }
        }

        // Describe the kernel RAM region
        if COMPATIBILITY_MASK.contains(!VSM_COMPATIBILITY_MASK) {
            self.directives.push(IgvmDirectiveHeader::RequiredMemory {
                gpa: param_block.kernel_base,
                compatibility_mask: COMPATIBILITY_MASK.get() & !VSM_COMPATIBILITY_MASK,
                number_of_bytes: param_block.kernel_min_size,
                vtl2_protectable: false,
            });
        }

        if COMPATIBILITY_MASK.contains(VSM_COMPATIBILITY_MASK) {
            self.directives.push(IgvmDirectiveHeader::RequiredMemory {
                gpa: param_block.kernel_base,
                compatibility_mask: VSM_COMPATIBILITY_MASK,
                number_of_bytes: param_block.kernel_min_size,
                vtl2_protectable: true,
            });
        }

        // Read the kernel image into a byte vector to be used by the boot
        // image builder.
        let kernel_image = fs::read(self.options.kernel.clone()).inspect_err(|_| {
            eprintln!("Failed to read kernel image {}", self.options.kernel);
        })?;

        // Invoke the boot image builder to construct the boot image.
        let boot_image_params = BootImageParams {
            boot_params: param_block,
            kernel_fs_start: self.gpa_map.kernel_fs.get_start(),
            kernel_fs_end: self.gpa_map.kernel_fs.get_start() + self.gpa_map.kernel_fs.get_size(),
            kernel_region_start: self.gpa_map.kernel.get_start(),
            kernel_region_page_count: self.gpa_map.kernel.get_size() / PAGE_SIZE_4K,
            stage2_start: self.gpa_map.stage2_image.get_start(),
            vtom: self.vtom,
        };
        let boot_image_info = prepare_boot_image(
            &boot_image_params,
            kernel_image.as_slice(),
            &mut |gpa, data, length| {
                self.add_data_pages(gpa, data, length, COMPATIBILITY_MASK.get())
                    .map_err(|e| {
                        eprintln!("{e}");
                        BootImageError::Host
                    })
            },
        )
        .map_err(|e| e.dyn_error())?;

        // Create the parameter areas for all host-supplied parameters.
        self.directives.push(IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: self
                .gpa_map
                .boot_param_layout
                .get_param_size(BootParamType::MemoryMap) as u64,
            parameter_area_index: IGVM_MEMORY_MAP_PA,
            initial_data: vec![],
        });
        self.directives.push(IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: self
                .gpa_map
                .boot_param_layout
                .get_param_size(BootParamType::Madt) as u64,
            parameter_area_index: IGVM_MADT_PA,
            initial_data: vec![],
        });
        self.directives.push(IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: self
                .gpa_map
                .boot_param_layout
                .get_param_size(BootParamType::General) as u64,
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
            .push(IgvmDirectiveHeader::Madt(IGVM_VHS_PARAMETER {
                parameter_area_index: IGVM_MADT_PA,
                byte_offset: 0,
            }));
        self.directives
            .push(IgvmDirectiveHeader::MemoryMap(IGVM_VHS_PARAMETER {
                parameter_area_index: IGVM_MEMORY_MAP_PA,
                byte_offset: 0,
            }));
        let param_base_gpa = self.gpa_map.boot_param_block.get_start();
        self.directives.push(IgvmDirectiveHeader::ParameterInsert(
            IGVM_VHS_PARAMETER_INSERT {
                gpa: self
                    .gpa_map
                    .boot_param_layout
                    .get_param_gpa(param_base_gpa, BootParamType::MemoryMap),
                compatibility_mask: COMPATIBILITY_MASK.get(),
                parameter_area_index: IGVM_MEMORY_MAP_PA,
            },
        ));
        self.directives.push(IgvmDirectiveHeader::ParameterInsert(
            IGVM_VHS_PARAMETER_INSERT {
                gpa: self
                    .gpa_map
                    .boot_param_layout
                    .get_param_gpa(param_base_gpa, BootParamType::Madt),
                compatibility_mask: COMPATIBILITY_MASK.get(),
                parameter_area_index: IGVM_MADT_PA,
            },
        ));
        self.directives.push(IgvmDirectiveHeader::ParameterInsert(
            IGVM_VHS_PARAMETER_INSERT {
                gpa: self
                    .gpa_map
                    .boot_param_layout
                    .get_param_gpa(param_base_gpa, BootParamType::General),
                compatibility_mask: COMPATIBILITY_MASK.get(),
                parameter_area_index: IGVM_GENERAL_PARAMS_PA,
            },
        ));

        if COMPATIBILITY_MASK.contains(SNP_COMPATIBILITY_MASK) {
            // Add the VMSA.
            self.directives.push(construct_vmsa(
                start_context,
                self.gpa_map.vmsa.get_start(),
                self.vtom,
                SNP_COMPATIBILITY_MASK,
                &self.options.sev_features,
                self.options.hypervisor,
            ));
        }

        if COMPATIBILITY_MASK.contains(VSM_COMPATIBILITY_MASK) {
            // Add the VSM register list.
            self.directives.push(IgvmDirectiveHeader::X64VbsVpContext {
                vtl: igvm::hv_defs::Vtl::Vtl2,
                registers: start_context.to_vec(),
                compatibility_mask: VSM_COMPATIBILITY_MASK,
            });
        }

        if COMPATIBILITY_MASK.contains(NATIVE_COMPATIBILITY_MASK) {
            // Include the native start context.
            self.directives.push(construct_native_start_context(
                start_context,
                NATIVE_COMPATIBILITY_MASK,
            ));
        }

        if COMPATIBILITY_MASK.contains(TDP_COMPATIBILITY_MASK) {
            // The presence of stage1 was already confirmed when the GPA map
            // was constructed, so it doesn't need to be tested again here.
            self.directives.push(construct_stage1_image(
                self.options.tdx_stage1.as_ref().unwrap(),
                self.gpa_map.stage1_image.get_start(),
                start_context,
                TDP_COMPATIBILITY_MASK,
            )?);
        }

        // Add the boot parameter block
        self.add_param_block(param_block);

        // Add optional filesystem image
        if let Some(fs) = &self.options.filesystem {
            self.add_data_pages_from_file(
                &fs.clone(),
                self.gpa_map.kernel_fs.get_start(),
                COMPATIBILITY_MASK.get(),
            )?;
        }

        if COMPATIBILITY_MASK.contains(SNP_COMPATIBILITY_MASK) {
            // CPUID page
            let cpuid_page = SnpCpuidPage::new()?;
            cpuid_page.add_directive(
                self.gpa_map.cpuid_page.get_start(),
                SNP_COMPATIBILITY_MASK,
                &mut self.directives,
            );

            // Secrets page
            self.add_empty_pages(
                boot_image_info.secrets_paddr,
                PAGE_SIZE_4K,
                SNP_COMPATIBILITY_MASK,
                IgvmPageDataType::SECRETS,
            )?;
        }
        if COMPATIBILITY_MASK.contains(TDP_COMPATIBILITY_MASK) {
            // Insert a zero page in place of the CPUID page
            self.add_empty_pages(
                self.gpa_map.cpuid_page.get_start(),
                self.gpa_map.cpuid_page.get_size(),
                TDP_COMPATIBILITY_MASK,
                IgvmPageDataType::NORMAL,
            )?;

            // Insert a zero page in place of the secrets page
            self.add_empty_pages(
                boot_image_info.secrets_paddr,
                PAGE_SIZE_4K,
                TDP_COMPATIBILITY_MASK,
                IgvmPageDataType::NORMAL,
            )?;
        }

        // Populate the empty region below the stage2 stack page.
        // This region is used for stage2 stack at runtime.
        self.add_empty_pages(
            self.gpa_map.base_addr,
            self.gpa_map.stage2_stack.get_start() - self.gpa_map.base_addr,
            COMPATIBILITY_MASK.get(),
            IgvmPageDataType::NORMAL,
        )?;

        // Populate the stage 2 binary.
        self.add_data_pages_from_file(
            &self.options.stage2.clone(),
            self.gpa_map.stage2_image.get_start(),
            COMPATIBILITY_MASK.get(),
        )?;

        // Populate the stage 2 stack.  This has different contents on each
        // platform.
        let stage2_stack = Stage2Stack::new(&self.gpa_map, &boot_image_info);
        if COMPATIBILITY_MASK.contains(SNP_COMPATIBILITY_MASK) {
            stage2_stack.add_directive(
                self.gpa_map.stage2_stack.get_start(),
                SvsmPlatformType::Snp,
                SNP_COMPATIBILITY_MASK,
                &mut self.directives,
            );
        }
        if COMPATIBILITY_MASK.contains(TDP_COMPATIBILITY_MASK) {
            stage2_stack.add_directive(
                self.gpa_map.stage2_stack.get_start(),
                SvsmPlatformType::Tdp,
                TDP_COMPATIBILITY_MASK,
                &mut self.directives,
            );
        }
        if COMPATIBILITY_MASK.contains(ANY_NATIVE_COMPATIBILITY_MASK) {
            stage2_stack.add_directive(
                self.gpa_map.stage2_stack.get_start(),
                SvsmPlatformType::Native,
                ANY_NATIVE_COMPATIBILITY_MASK,
                &mut self.directives,
            );
        }

        if COMPATIBILITY_MASK.contains(ANY_NATIVE_COMPATIBILITY_MASK) {
            // Include initial page tables.
            construct_init_page_tables(
                self.gpa_map.init_page_tables.get_start(),
                ANY_NATIVE_COMPATIBILITY_MASK,
                &mut self.directives,
            );
        }

        // If the target includes a non-isolated platform, then insert the
        // SIPI startup stub.  Also include the SIPI stub with TDX since it is
        // used for AP startup.
        let sipi_compat_mask = ANY_NATIVE_COMPATIBILITY_MASK | TDP_COMPATIBILITY_MASK;
        if COMPATIBILITY_MASK.contains(sipi_compat_mask) {
            add_sipi_stub(sipi_compat_mask, &mut self.directives);
        }

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
        compatibility_mask: u32,
    ) -> Result<(), Box<dyn Error>> {
        let mut gpa = gpa_start;
        let mut in_file = File::open(path).inspect_err(|_| {
            eprintln!("Could not open input file {path}");
        })?;
        let mut buf = vec![0; 4096];

        while let Ok(len) = in_file.read(&mut buf) {
            if len == 0 {
                break;
            }
            self.directives
                .push(Self::new_page_data(gpa, compatibility_mask, buf));
            gpa += PAGE_SIZE_4K;
            buf = vec![0; 4096];
        }
        Ok(())
    }

    fn add_param_block(&mut self, param_block: &BootParamBlock) {
        let mut data = param_block.as_bytes().to_vec();
        data.resize(PAGE_SIZE_4K as usize, 0);

        self.directives.push(IgvmDirectiveHeader::PageData {
            gpa: self.gpa_map.boot_param_block.get_start(),
            compatibility_mask: COMPATIBILITY_MASK.get(),
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data,
        });
    }

    fn add_guest_context(&mut self, guest_context: &InitialGuestContext) {
        let mut data = guest_context.as_bytes().to_vec();
        data.resize(PAGE_SIZE_4K as usize, 0);

        self.directives.push(IgvmDirectiveHeader::PageData {
            gpa: self.gpa_map.boot_param_layout.get_param_gpa(
                self.gpa_map.boot_param_block.get_start(),
                BootParamType::GuestContext,
            ),
            compatibility_mask: COMPATIBILITY_MASK.get(),
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data,
        });
    }

    fn add_data_pages(
        &mut self,
        mut gpa: u64,
        data: Option<&[u8]>,
        mut length: u64,
        compatibility_mask: u32,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(data_slice) = data {
            assert!(length >= data_slice.len() as u64);
            for chunk in data_slice.chunks(PAGE_SIZE_4K as usize) {
                self.directives.push(IgvmDirectiveHeader::PageData {
                    gpa,
                    compatibility_mask,
                    flags: IgvmPageDataFlags::new(),
                    data_type: IgvmPageDataType::NORMAL,
                    data: chunk.to_vec(),
                });
                gpa += PAGE_SIZE_4K;
                length -= PAGE_SIZE_4K;
            }
        }
        if length != 0 {
            self.add_empty_pages(gpa, length, compatibility_mask, IgvmPageDataType::NORMAL)?;
        }

        Ok(())
    }

    fn add_empty_pages(
        &mut self,
        gpa_start: u64,
        size: u64,
        compatibility_mask: u32,
        data_type: IgvmPageDataType,
    ) -> Result<(), Box<dyn Error>> {
        for gpa in (gpa_start..(gpa_start + size)).step_by(PAGE_SIZE_4K as usize) {
            self.directives.push(IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask,
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
