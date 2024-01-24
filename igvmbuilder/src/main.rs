// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use clap::{Parser, ValueEnum};
use igvm::snp_defs::{SevFeatures, SevVmsa};
use igvm::{IgvmDirectiveHeader, IgvmFile, IgvmPlatformHeader, IgvmRevision};
use igvm_defs::{
    IgvmPageDataFlags, IgvmPageDataType, IgvmPlatformType, IGVM_VHS_PARAMETER,
    IGVM_VHS_PARAMETER_INSERT, IGVM_VHS_SUPPORTED_PLATFORM, PAGE_SIZE_4K,
};
use igvm_params::{IgvmParamBlock, IgvmParamBlockFwInfo, IgvmParamBlockFwMem};
use ovmfmeta::parse_ovmf_metadata;
use std::error::Error;
use std::fs::metadata;
use std::io::Write;
use std::mem::size_of;
use std::vec;
use std::{fs::File, io::Read};
use zerocopy::AsBytes;
use zerocopy::FromZeroes;

mod igvm_params;
mod ovmfmeta;

const COMPATIBILITY_MASK: u32 = 1;

// Parameter area indices
const IGVM_GENERAL_PARAMS_PA: u32 = 0;
const IGVM_MEMORY_MAP_PA: u32 = 1;

#[derive(Parser, Debug)]
struct Args {
    /// Stage 2 binary file
    #[arg(short, long)]
    stage2: String,

    /// Kernel elf file
    #[arg(short, long)]
    kernel: String,

    /// Optional filesystem image
    #[arg(long)]
    filesystem: Option<String>,

    /// Optional firmware file, e.g. OVMF.fd
    #[arg(short, long)]
    firmware: Option<String>,

    /// Output filename for the generated IGVM file
    #[arg(short, long)]
    output: String,

    /// COM port to use for the SVSM console. Valid values are 1-4
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(i32).range(1..=4))]
    comport: i32,

    /// Hypervisor to generate IGVM file for
    #[arg(value_enum)]
    hypervisor: Hypervisor,

    /// Print verbose output
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Hypervisor {
    /// Build an IGVM file compatible with QEMU
    QEMU,

    /// Build an IGVM file compatible with Hyper-V
    HyperV,
}

#[repr(C, packed(1))]
#[derive(AsBytes)]
struct Stage2Stack {
    pub kernel_start: u32,
    pub kernel_end: u32,
    pub filesystem_start: u32,
    pub filesystem_end: u32,
    pub igvm_param_block: u32,
    pub reserved: u32,
}

#[repr(C, packed(1))]
#[derive(AsBytes, Copy, Clone, Default)]
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
        Self {
            eax_in,
            ecx_in: 0,
            xcr0: 0,
            xss: 0,
            eax_out: 0,
            ebx_out: 0,
            ecx_out: 0,
            edx_out: 0,
            reserved: 0,
        }
    }

    pub fn new2(eax_in: u32, ecx_in: u32) -> Self {
        Self {
            eax_in,
            ecx_in,
            xcr0: 0,
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
#[derive(AsBytes)]
struct SnpCpuidPage {
    count: u32,
    reserved: [u32; 3],
    cpuid_info: [SnpCpuidLeaf; 64],
}

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
    pub fn add(&mut self, leaf: SnpCpuidLeaf) -> Result<(), Box<dyn Error>> {
        if self.count == 64 {
            return Err("Maximum number of CPUID leaves exceeded".into());
        }
        self.cpuid_info[self.count as usize] = leaf;
        self.count += 1;
        Ok(())
    }
}

fn port_address(port: i32) -> u16 {
    match port {
        1 => 0x3f8,
        2 => 0x2f8,
        3 => 0x3e8,
        4 => 0x2e8,
        _ => 0,
    }
}

fn new_platform(compatibility_mask: u32, platform_type: IgvmPlatformType) -> IgvmPlatformHeader {
    IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
        compatibility_mask,
        highest_vtl: 2,
        platform_type,
        platform_version: 1,
        shared_gpa_boundary: 0,
    })
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

fn construct_initial_vmsa(gpa_start: u64) -> Result<IgvmDirectiveHeader, Box<dyn Error>> {
    let mut vmsa_box = SevVmsa::new_box_zeroed();
    let vmsa = vmsa_box.as_mut();

    // Establish CS as a 32-bit code selector.
    vmsa.cs.attrib = 0xc9b;
    vmsa.cs.limit = 0xffffffff;
    vmsa.cs.selector = 0x08;

    // Establish all data segments as generic data selectors.
    vmsa.ds.attrib = 0xa93;
    vmsa.ds.limit = 0xffffffff;
    vmsa.ds.selector = 0x10;
    vmsa.ss = vmsa.ds;
    vmsa.es = vmsa.ds;
    vmsa.fs = vmsa.ds;
    vmsa.gs = vmsa.ds;

    // EFER.SVME.
    vmsa.efer = 0x1000;

    // CR0.PE | CR0.NE.
    vmsa.cr0 = 0x21;

    // CR4.MCE.
    vmsa.cr4 = 0x40;

    vmsa.pat = 0x0007040600070406;
    vmsa.xcr0 = 1;
    vmsa.rflags = 2;
    vmsa.rip = 0x10000;
    vmsa.rsp = vmsa.rip - size_of::<Stage2Stack>() as u64;

    let mut features = SevFeatures::new();
    features.set_snp(true);
    features.set_restrict_injection(true);
    vmsa.sev_features = features;

    Ok(IgvmDirectiveHeader::SnpVpContext {
        gpa: gpa_start,
        compatibility_mask: COMPATIBILITY_MASK,
        vp_index: 0,
        vmsa: vmsa_box,
    })
}

fn construct_cpuid_page(gpa_map: &GpaMap) -> Result<IgvmDirectiveHeader, Box<dyn Error>> {
    let mut cpuid_page = SnpCpuidPage::default();
    cpuid_page.add(SnpCpuidLeaf::new1(0x8000001f))?;
    cpuid_page.add(SnpCpuidLeaf::new2(1, 1))?;
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
    cpuid_page.add(SnpCpuidLeaf::new1(13))?;
    cpuid_page.add(SnpCpuidLeaf::new2(13, 1))?;
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

    let cpuid_data = unsafe {
        let ptr = &cpuid_page as *const SnpCpuidPage as *const [u8; size_of::<SnpCpuidPage>()];
        &*ptr
    };
    if cpuid_data.len() > PAGE_SIZE_4K as usize {
        return Err("CPUID page size exceeds 4K".into());
    }
    let mut cpuid_page = [0u8; PAGE_SIZE_4K as usize];
    cpuid_page[..cpuid_data.len()].clone_from_slice(cpuid_data);

    Ok(IgvmDirectiveHeader::PageData {
        gpa: gpa_map.cpuid_page.start,
        compatibility_mask: COMPATIBILITY_MASK,
        flags: IgvmPageDataFlags::new(),
        data_type: IgvmPageDataType::CPUID_DATA,
        data: cpuid_page.to_vec(),
    })
}

fn add_empty_pages(
    gpa_start: u64,
    size: u64,
    data_type: IgvmPageDataType,
    directives: &mut Vec<IgvmDirectiveHeader>,
) -> Result<(), Box<dyn Error>> {
    for gpa in (gpa_start..(gpa_start + size)).step_by(PAGE_SIZE_4K as usize) {
        directives.push(IgvmDirectiveHeader::PageData {
            gpa,
            compatibility_mask: COMPATIBILITY_MASK,
            flags: IgvmPageDataFlags::new(),
            data_type,
            data: vec![],
        });
    }
    Ok(())
}

fn add_data_pages_from_file(
    path: &String,
    gpa_start: u64,
    directives: &mut Vec<IgvmDirectiveHeader>,
) -> Result<(), Box<dyn Error>> {
    let mut gpa = gpa_start;
    let mut in_file = File::open(path).expect("Could not open input file");
    let mut buf = vec![0; 4096];

    while let Ok(len) = in_file.read(&mut buf) {
        if len == 0 {
            break;
        }
        directives.push(new_page_data(gpa, 1, buf));
        gpa += PAGE_SIZE_4K;
        buf = vec![0; 4096];
    }
    Ok(())
}

fn construct_param_block(
    param_block: &IgvmParamBlock,
    gpa_map: &GpaMap,
) -> Result<IgvmDirectiveHeader, Box<dyn Error>> {
    let param_block_data = unsafe {
        let ptr = param_block as *const IgvmParamBlock as *const [u8; size_of::<IgvmParamBlock>()];
        &*ptr
    };
    if param_block_data.len() > PAGE_SIZE_4K as usize {
        return Err("IGVM parameter block size exceeds 4K".into());
    }
    let mut param_block_page = [0u8; PAGE_SIZE_4K as usize];
    param_block_page[..param_block_data.len()].clone_from_slice(param_block_data);

    Ok(IgvmDirectiveHeader::PageData {
        gpa: gpa_map.igvm_param_block.start,
        compatibility_mask: COMPATIBILITY_MASK,
        flags: IgvmPageDataFlags::new(),
        data_type: IgvmPageDataType::NORMAL,
        data: param_block_page.to_vec(),
    })
}

#[derive(Debug, Copy, Clone)]
struct GpaRange {
    start: u64,
    end: u64,
    size: u64,
}

impl GpaRange {
    fn new(start: u64, size: u64) -> Result<Self, Box<dyn Error>> {
        if (start & 0xfff) != 0 {
            return Err("Range is not page aligned".into());
        }
        let page_size = (size + (PAGE_SIZE_4K - 1)) & !(PAGE_SIZE_4K - 1);
        Ok(Self {
            start,
            end: start + page_size,
            size,
        })
    }

    fn new_page(start: u64) -> Result<Self, Box<dyn Error>> {
        Self::new(start, PAGE_SIZE_4K)
    }
}

#[derive(Debug)]
struct GpaMap {
    low_memory: GpaRange,
    stage2_stack: GpaRange,
    stage2_image: GpaRange,
    stage2_free: GpaRange,
    secrets_page: GpaRange,
    cpuid_page: GpaRange,
    kernel_elf: GpaRange,
    kernel_fs: GpaRange,
    igvm_param_block: GpaRange,
    general_params: GpaRange,
    memory_map: GpaRange,
    firmware: GpaRange,
    kernel: GpaRange,
    vmsa: GpaRange,
}

impl GpaMap {
    fn new(args: &Args) -> Result<Self, Box<dyn Error>> {
        //   0x000000-0x00EFFF: zero-filled (must be pre-validated)
        //   0x00F000-0x00FFFF: initial stage 2 stack page
        //   0x010000-0x0nnnnn: stage 2 image
        //   0x0nnnnn-0x09DFFF: zero-filled (must be pre-validated)
        //   0x09E000-0x09EFFF: Secrets page
        //   0x09F000-0x09FFFF: CPUID page
        //   0x100000-0x1nnnnn: kernel
        //   0x1nnnnn-0x1nnnnn: filesystem
        //   0x1nnnnn-0x1nnnnn: IGVM parameter block
        //   0x1nnnnn-0x1nnnnn: general and memory map parameter pages
        //   0xFFnn0000-0xFFFFFFFF: OVMF firmware (QEMU only, if specified)

        // Obtain the lengths of the binary files
        let stage2_len = metadata(&args.stage2)?.len() as usize;
        let kernel_elf_len = metadata(&args.kernel)?.len() as usize;
        let kernel_fs_len = if let Some(fs) = &args.filesystem {
            metadata(fs)?.len() as usize
        } else {
            0
        };

        let stage2_image = GpaRange::new(0x10000, stage2_len as u64)?;

        // Plan to load the kernel image at a base address of 1 MB unless it must
        // be relocated due to firmware.
        let kernel_address = 1 << 20;
        // TODO: If Hyper-V then parse the firmware and determine if the kernel
        // address changes.

        let kernel_elf = GpaRange::new(kernel_address, kernel_elf_len as u64)?;
        let kernel_fs = GpaRange::new(kernel_elf.end, kernel_fs_len as u64)?;

        // Calculate the firmware range
        let firmware = if let Some(firmware) = &args.firmware {
            match args.hypervisor {
                Hypervisor::QEMU => {
                    // OVMF must be located to end at 4GB.
                    let len = metadata(firmware)?.len() as usize;
                    if len > 0xffffffff {
                        return Err("OVMF firmware is too large".into());
                    }
                    GpaRange::new((0xffffffff - len + 1) as u64, len as u64)?
                }
                Hypervisor::HyperV => return Err("Hyper-V firmware not yet implemented".into()),
            }
        } else {
            GpaRange::new(0, 0)?
        };

        // Calculate the kernel size and base.
        let kernel = match args.hypervisor {
            Hypervisor::QEMU => {
                // Place the kernel area at 512 GB with a size of 16 MB.
                GpaRange::new(0x0000008000000000, 0x01000000)?
            }
            Hypervisor::HyperV => {
                // Place the kernel area at 64 MB with a size of 16 MB.
                GpaRange::new(0x04000000, 0x01000000)?
            }
        };
        let gpa_map = Self {
            low_memory: GpaRange::new(0, 0xf000)?,
            stage2_stack: GpaRange::new_page(0xf000)?,
            stage2_image,
            stage2_free: GpaRange::new(stage2_image.end, 0x9e000 - &stage2_image.end)?,
            secrets_page: GpaRange::new_page(0x9e000)?,
            cpuid_page: GpaRange::new_page(0x9f000)?,
            kernel_elf,
            kernel_fs,
            igvm_param_block: GpaRange::new_page(kernel_elf.end)?,
            general_params: GpaRange::new_page(kernel_elf.end + PAGE_SIZE_4K)?,
            memory_map: GpaRange::new_page(kernel_elf.end + 2 * PAGE_SIZE_4K)?,
            firmware,
            kernel,
            vmsa: GpaRange::new_page(kernel.start)?,
        };
        if args.verbose {
            println!("GPA Map: {gpa_map:#X?}");
        }
        Ok(gpa_map)
    }
}

fn create_param_block(args: &Args, gpa_map: &GpaMap) -> Result<IgvmParamBlock, Box<dyn Error>> {
    let param_page_offset = PAGE_SIZE_4K as u32;
    let memory_map_offset = param_page_offset + PAGE_SIZE_4K as u32;
    let memory_map_end_offset = memory_map_offset + PAGE_SIZE_4K as u32;

    let firmware = IgvmParamBlockFwInfo {
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

    // Most of the parameter block can be initialised with constants.
    let mut param_block = IgvmParamBlock {
        param_area_size: memory_map_end_offset,
        param_page_offset,
        memory_map_offset,
        guest_context_offset: 0,
        cpuid_page: gpa_map.cpuid_page.start as u32,
        secrets_page: gpa_map.secrets_page.start as u32,
        debug_serial_port: port_address(args.comport),
        _reserved: [0u16; 3],
        firmware,
        kernel_reserved_size: PAGE_SIZE_4K as u32, // Reserved for VMSA
        kernel_size: gpa_map.kernel.size as u32,
        kernel_base: gpa_map.kernel.start,
        vtom: 0,
    };

    // Populate the firmware metadata.
    if let Some(firmware) = &args.firmware {
        match args.hypervisor {
            Hypervisor::QEMU => {
                parse_ovmf_metadata(firmware, &mut param_block.firmware)?;
                // OVMF must be located to end at 4GB.
                let len = metadata(firmware)?.len() as usize;
                if len > 0xffffffff {
                    return Err("OVMF firmware is too large".into());
                }
                param_block.firmware.start = (0xffffffff - len + 1) as u32;
                param_block.firmware.size = len as u32;
            }
            Hypervisor::HyperV => return Err("Hyper-V firmware not yet implemented".into()),
        }
    };

    // Calculate the kernel size and base.
    match args.hypervisor {
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

fn construct_stage2_stack(gpa_map: &GpaMap) -> Result<IgvmDirectiveHeader, Box<dyn Error>> {
    let stage2_stack = Stage2Stack {
        kernel_start: gpa_map.kernel_elf.start as u32,
        kernel_end: (gpa_map.kernel_elf.start + gpa_map.kernel_elf.size) as u32,
        filesystem_start: gpa_map.kernel_fs.start as u32,
        filesystem_end: gpa_map.kernel_fs.end as u32,
        igvm_param_block: gpa_map.igvm_param_block.start as u32,
        reserved: 0,
    };
    let mut stage2_stack_data = stage2_stack.as_bytes().to_vec();
    let mut stage2_stack_page = vec![0u8; PAGE_SIZE_4K as usize - stage2_stack_data.len()];
    stage2_stack_page.append(&mut stage2_stack_data);

    if stage2_stack_page.len() > PAGE_SIZE_4K as usize {
        return Err("Stage 2 stack size exceeds 4K".into());
    }

    Ok(IgvmDirectiveHeader::PageData {
        gpa: gpa_map.stage2_stack.start,
        compatibility_mask: COMPATIBILITY_MASK,
        flags: IgvmPageDataFlags::new(),
        data_type: IgvmPageDataType::NORMAL,
        data: stage2_stack_page,
    })
}

fn build_directives(
    args: &Args,
    directives: &mut Vec<IgvmDirectiveHeader>,
) -> Result<(), Box<dyn Error>> {
    // Start by calculating the GPA memory map.
    let gpa_map = GpaMap::new(args)?;

    // Build the parameter block as this is used for positioning
    // some of the GPA regions.
    let param_block = create_param_block(args, &gpa_map)?;

    // Describe the kernel RAM region
    directives.push(IgvmDirectiveHeader::RequiredMemory {
        gpa: param_block.kernel_base,
        compatibility_mask: COMPATIBILITY_MASK,
        number_of_bytes: param_block.kernel_size,
        vtl2_protectable: false,
    });

    // Create the two parameter areas for memory map and general parameters.
    directives.push(IgvmDirectiveHeader::ParameterArea {
        number_of_bytes: PAGE_SIZE_4K,
        parameter_area_index: IGVM_MEMORY_MAP_PA,
        initial_data: vec![],
    });
    directives.push(IgvmDirectiveHeader::ParameterArea {
        number_of_bytes: PAGE_SIZE_4K,
        parameter_area_index: IGVM_GENERAL_PARAMS_PA,
        initial_data: vec![],
    });
    directives.push(IgvmDirectiveHeader::VpCount(IGVM_VHS_PARAMETER {
        parameter_area_index: IGVM_GENERAL_PARAMS_PA,
        byte_offset: 0,
    }));
    directives.push(IgvmDirectiveHeader::EnvironmentInfo(IGVM_VHS_PARAMETER {
        parameter_area_index: IGVM_GENERAL_PARAMS_PA,
        byte_offset: 4,
    }));
    directives.push(IgvmDirectiveHeader::MemoryMap(IGVM_VHS_PARAMETER {
        parameter_area_index: IGVM_MEMORY_MAP_PA,
        byte_offset: 0,
    }));
    directives.push(IgvmDirectiveHeader::ParameterInsert(
        IGVM_VHS_PARAMETER_INSERT {
            gpa: gpa_map.memory_map.start,
            compatibility_mask: COMPATIBILITY_MASK,
            parameter_area_index: IGVM_MEMORY_MAP_PA,
        },
    ));
    directives.push(IgvmDirectiveHeader::ParameterInsert(
        IGVM_VHS_PARAMETER_INSERT {
            gpa: gpa_map.general_params.start,
            compatibility_mask: COMPATIBILITY_MASK,
            parameter_area_index: IGVM_GENERAL_PARAMS_PA,
        },
    ));

    // Place the VMSA at the base of the kernel region.
    directives.push(construct_initial_vmsa(gpa_map.vmsa.start)?);

    // Populate the firmware pages.
    if let Some(firmware) = &args.firmware {
        add_data_pages_from_file(firmware, gpa_map.firmware.start, directives)?;
    }

    // Add the IGVM parameter block
    directives.push(construct_param_block(&param_block, &gpa_map)?);

    // Add the kernel elf binary
    add_data_pages_from_file(&args.kernel, gpa_map.kernel_elf.start, directives)?;

    // CPUID page
    directives.push(construct_cpuid_page(&gpa_map)?);

    // Secrets page
    add_empty_pages(
        gpa_map.secrets_page.start,
        gpa_map.secrets_page.size,
        IgvmPageDataType::SECRETS,
        directives,
    )?;

    // Populate the empty region above the stage 2 binary.
    add_empty_pages(
        gpa_map.stage2_free.start,
        gpa_map.stage2_free.size,
        IgvmPageDataType::NORMAL,
        directives,
    )?;

    // Populate the stage 2 binary.
    add_data_pages_from_file(&args.stage2, gpa_map.stage2_image.start, directives)?;

    // Populate the stage 2 stack.
    directives.push(construct_stage2_stack(&gpa_map)?);

    // Populate the empty region at the bottom of RAM.
    add_empty_pages(
        gpa_map.low_memory.start,
        gpa_map.low_memory.size,
        IgvmPageDataType::NORMAL,
        directives,
    )?;

    if args.verbose {
        println!("{param_block:#X?}");
    }
    Ok(())
}

fn create_igvm(args: &Args) -> Result<(), Box<dyn Error>> {
    let mut directives: Vec<IgvmDirectiveHeader> = vec![];
    build_directives(args, &mut directives)?;

    let file = IgvmFile::new(
        IgvmRevision::V1,
        vec![new_platform(0x1, IgvmPlatformType::SEV_SNP)],
        vec![],
        directives,
    )
    .expect("Failed to create file");
    let mut binary_file = Vec::new();
    file.serialize(&mut binary_file).unwrap();

    let mut file = File::create(&args.output).expect("Could not open file");
    file.write_all(binary_file.as_slice())
        .expect("Failed to write file");

    Ok(())
}

fn main() {
    let args = Args::parse();
    let _ = create_igvm(&args);
}
