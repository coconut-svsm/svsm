// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange <jlange@microsoft.com>

#![no_std]

mod defs;
mod elf;
mod error;
mod heap;
mod page_tables;
mod symbols;

use crate::elf::get_elf_sizes;
use crate::elf::load_kernel_elf;
use crate::heap::create_kernel_heap;
use crate::page_tables::round_to_pages;
use crate::page_tables::setup_kernel_page_tables;
use crate::symbols::load_kernel_symbols;

pub use crate::defs::*;
pub use crate::error::BootImageError;

use ::elf::Elf64File;
use bootdefs::kernel_launch::INITIAL_KERNEL_STACK_WORDS;
use bootdefs::kernel_launch::InitialKernelStack;
use bootdefs::kernel_launch::KernelLaunchInfo;
use igvm_defs::PAGE_SIZE_4K;
use zerocopy::IntoBytes;

pub fn prepare_boot_image<F>(
    boot_image_params: &BootImageParams<'_>,
    kernel_elf_bytes: &[u8],
    add_page_data: &mut F,
) -> Result<BootImageInfo, BootImageError>
where
    F: FnMut(u64, Option<&[u8]>, u64) -> Result<(), BootImageError>,
{
    // Parse the ELF image so it can be loaded.
    let kernel_elf = Elf64File::read(kernel_elf_bytes).map_err(|_| BootImageError::Elf)?;

    // Determine the virtual and physical address span of the kernel ELF image.
    let kernel_elf_sizes = get_elf_sizes(&kernel_elf);

    // Determine whether this image will reserve space in the kernel heap for
    // a VMSA.  To maintain consistency across architectures, this is always
    // set based on the VMSA address that will be used under SNP, and if the
    // image is loaded on a non-SNP architecture, the reserved page will be
    // freed during heap initialization.
    let vmsa_in_kernel_heap = boot_image_params.boot_params.vmsa_in_kernel_range != 0;

    // Initialize the kernel page heap so it can be used to manage physical
    // allocations for the boot image.  The page heap starts at the first
    // physical address after the loaded kernel ELF image, and at a virtual
    // address following the end of the kernel ELF image.  A gap of one page
    // is chosen to serve as a guard page for the initial stack.
    let mut kernel_heap = create_kernel_heap(
        boot_image_params.kernel_region_start,
        boot_image_params.kernel_region_page_count,
        &kernel_elf_sizes,
        PAGE_SIZE_4K,
        vmsa_in_kernel_heap,
    )?;

    // Alloacte 32 KB for the intiial stack.  This must come at the base of
    // the kernel heap so it is preceded by a guard page.
    let stack_page_count = 8;
    let stack_size = stack_page_count * PAGE_SIZE_4K;
    let (initial_stack_paddr, initial_stack_base) = kernel_heap.allocate_pages(stack_page_count)?;

    // Initialize the page tables that will be used for mapping kernel data.
    let mut kernel_page_tables =
        setup_kernel_page_tables(kernel_elf_sizes.virt_base, &mut kernel_heap, add_page_data)?;

    // Load the kernel image and map it into the kernel page tables.
    let kernel_entry = load_kernel_elf(
        &kernel_elf,
        boot_image_params.kernel_region_start,
        kernel_elf_sizes.phys_page_count,
        &mut kernel_page_tables,
        add_page_data,
    )?;

    // Map the heap into the page tables.
    kernel_heap.map(&mut kernel_page_tables)?;

    // Allocate space in the kernel heap to hold the parameters.  This must be
    // large enough to include both the measured boot parameters and the
    // unmeasured boot parameters.
    let (boot_params_paddr, boot_params_vaddr) = kernel_heap.allocate_pages(round_to_pages(
        boot_image_params.boot_params.param_area_size as u64,
    ))?;

    // Copy the boot data into the image.
    add_page_contents(
        add_page_data,
        boot_params_paddr,
        boot_image_params.boot_params.as_bytes(),
    )?;

    // Allocate space for the CPUID and secrets pages.
    let (cpuid_paddr, cpuid_vaddr) = kernel_heap.allocate_pages(1)?;
    let (secrets_paddr, secrets_vaddr) = kernel_heap.allocate_pages(1)?;

    // Allocate space for the kernel symbol tables if desired.
    let (symtab, strtab) = load_kernel_symbols(&kernel_elf, &mut kernel_heap, add_page_data)?;

    // Now that all mapping is complete, add the page table contents into the
    // boot image.
    let (paging_root, total_pt_pages) = kernel_page_tables.add_to_image(add_page_data)?;

    // Allocate memory to hold the kernel launch info block.
    let (launch_info_paddr, launch_info_vaddr) =
        kernel_heap.allocate_pages(round_to_pages(size_of::<KernelLaunchInfo>() as u64))?;

    let launch_info = KernelLaunchInfo {
        kernel_region_phys_start: boot_image_params.kernel_region_start,
        kernel_region_phys_end: boot_image_params.kernel_region_start
            + (boot_image_params.kernel_region_page_count * PAGE_SIZE_4K),
        heap_area_phys_start: kernel_heap.phys_base(),
        heap_area_virt_start: kernel_heap.virt_base(),
        heap_area_page_count: kernel_heap.page_count(),
        heap_area_allocated: kernel_heap.next_free(),
        kernel_region_virt_start: kernel_elf_sizes.virt_base,
        kernel_symtab_start: symtab.start,
        kernel_symtab_len: symtab.length,
        kernel_strtab_start: strtab.start,
        kernel_strtab_len: strtab.length,
        kernel_fs_start: boot_image_params.kernel_fs_start,
        kernel_fs_end: boot_image_params.kernel_fs_end,
        stage2_start: boot_image_params.stage2_start,
        cpuid_page: cpuid_vaddr,
        secrets_page: secrets_vaddr,
        boot_params_virt_addr: boot_params_vaddr,
        vtom: boot_image_params.vtom,
        debug_serial_port: boot_image_params.boot_params.debug_serial_port,
        use_alternate_injection: false,
        kernel_page_table_vaddr: kernel_page_tables.root_vaddr(),
        suppress_svsm_interrupts: false,
        vmsa_in_kernel_heap,
        lowmem_validated: false,
        _reserved: Default::default(),
    };
    add_page_contents(add_page_data, launch_info_paddr, launch_info.as_bytes())?;

    // Now add the contents of the initial stack.  All of the stack pages will
    // be added as zero-filled pages except the final page, which holds the
    // launch state.
    let stack_zeroed_size = stack_size - PAGE_SIZE_4K;
    add_page_data(initial_stack_paddr, None, stack_zeroed_size)?;
    let initial_stack_data = InitialKernelStack {
        _reserved: [0; 512 - INITIAL_KERNEL_STACK_WORDS],
        paging_root,
        launch_info_vaddr,
        stack_limit: initial_stack_base,
    };
    add_page_data(
        initial_stack_paddr + stack_zeroed_size,
        Some(initial_stack_data.as_bytes()),
        PAGE_SIZE_4K,
    )?;

    let info = BootImageInfo {
        boot_params_paddr,
        kernel_launch_info: launch_info_vaddr,
        cpuid_paddr,
        secrets_paddr,
        kernel_pdpt_paddr: kernel_page_tables.kernel_pdpt_paddr(),
        kernel_pml4e_index: kernel_page_tables.kernel_pml4e_index(),
        total_pt_pages,
        kernel_page_tables_base: paging_root,
        context: BootImageContext {
            entry_point: kernel_entry,
            paging_root,
            initial_stack: initial_stack_base + (stack_page_count * PAGE_SIZE_4K)
                - (INITIAL_KERNEL_STACK_WORDS * 8) as u64,
        },
    };

    Ok(info)
}
