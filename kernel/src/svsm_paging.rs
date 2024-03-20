// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::config::SvsmConfig;
use crate::cpu::ghcb::current_ghcb;
use crate::elf;
use crate::error::SvsmError;
use crate::igvm_params::IgvmParams;
use crate::mm;
use crate::mm::pagetable::{set_init_pgtable, PTEntryFlags, PageTable, PageTableRef};
use crate::mm::PerCPUPageMappingGuard;
use crate::sev::ghcb::PageStateChangeOp;
use crate::sev::{pvalidate, PvalidateOp};
use crate::types::PageSize;
use crate::utils::MemoryRegion;
use bootlib::kernel_launch::KernelLaunchInfo;

struct IgvmParamInfo<'a> {
    virt_addr: VirtAddr,
    igvm_params: Option<IgvmParams<'a>>,
}

pub fn init_page_table(
    launch_info: &KernelLaunchInfo,
    kernel_elf: &elf::Elf64File<'_>,
) -> Result<(), SvsmError> {
    let vaddr = mm::alloc::allocate_zeroed_page().expect("Failed to allocate root page-table");
    let mut pgtable = PageTableRef::new(unsafe { &mut *vaddr.as_mut_ptr::<PageTable>() });
    let igvm_param_info = if launch_info.igvm_params_virt_addr != 0 {
        let addr = VirtAddr::from(launch_info.igvm_params_virt_addr);
        IgvmParamInfo {
            virt_addr: addr,
            igvm_params: Some(IgvmParams::new(addr)?),
        }
    } else {
        IgvmParamInfo {
            virt_addr: VirtAddr::null(),
            igvm_params: None,
        }
    };

    // Install mappings for the kernel's ELF segments each.
    // The memory backing the kernel ELF segments gets allocated back to back
    // from the physical memory region by the Stage2 loader.
    let mut phys = PhysAddr::from(launch_info.kernel_region_phys_start);
    for segment in kernel_elf.image_load_segment_iter(launch_info.kernel_region_virt_start) {
        let vaddr_start = VirtAddr::from(segment.vaddr_range.vaddr_begin);
        let vaddr_end = VirtAddr::from(segment.vaddr_range.vaddr_end);
        let aligned_vaddr_end = vaddr_end.page_align_up();
        let segment_len = aligned_vaddr_end - vaddr_start;
        let flags = if segment.flags.contains(elf::Elf64PhdrFlags::EXECUTE) {
            PTEntryFlags::exec()
        } else if segment.flags.contains(elf::Elf64PhdrFlags::WRITE) {
            PTEntryFlags::data()
        } else {
            PTEntryFlags::data_ro()
        };

        let vregion = MemoryRegion::new(vaddr_start, segment_len);
        pgtable
            .map_region(vregion, phys, flags)
            .expect("Failed to map kernel ELF segment");

        phys = phys + segment_len;
    }

    // Map the IGVM parameters if present.
    if let Some(ref igvm_params) = igvm_param_info.igvm_params {
        let vregion = MemoryRegion::new(igvm_param_info.virt_addr, igvm_params.size());
        pgtable
            .map_region(
                vregion,
                PhysAddr::from(launch_info.igvm_params_phys_addr),
                PTEntryFlags::data(),
            )
            .expect("Failed to map IGVM parameters");
    }

    // Map subsequent heap area.
    let heap_vregion = MemoryRegion::new(
        VirtAddr::from(launch_info.heap_area_virt_start),
        launch_info.heap_area_size as usize,
    );
    pgtable
        .map_region(
            heap_vregion,
            PhysAddr::from(launch_info.heap_area_phys_start),
            PTEntryFlags::data(),
        )
        .expect("Failed to map heap");

    pgtable.load();

    set_init_pgtable(pgtable);
    Ok(())
}

fn invalidate_boot_memory_region(
    config: &SvsmConfig<'_>,
    region: MemoryRegion<PhysAddr>,
) -> Result<(), SvsmError> {
    log::info!(
        "Invalidating boot region {:018x}-{:018x}",
        region.start(),
        region.end()
    );

    for paddr in region.iter_pages(PageSize::Regular) {
        let guard = PerCPUPageMappingGuard::create_4k(paddr)?;
        let vaddr = guard.virt_addr();

        pvalidate(vaddr, PageSize::Regular, PvalidateOp::Invalid)?;
    }

    if config.page_state_change_required() && !region.is_empty() {
        current_ghcb()
            .page_state_change(
                region.start(),
                region.end(),
                PageSize::Regular,
                PageStateChangeOp::PscShared,
            )
            .expect("Failed to invalidate Stage2 memory");
    }

    Ok(())
}

pub fn invalidate_early_boot_memory(
    config: &SvsmConfig<'_>,
    launch_info: &KernelLaunchInfo,
) -> Result<(), SvsmError> {
    // Early boot memory must be invalidated after changing to the SVSM page
    // page table to avoid invalidating page tables currently in use.  Always
    // invalidate stage 2 memory, unless firmware is loaded into low memory.
    // Also invalidate the boot data if required.
    if !config.fw_in_low_memory() {
        let stage2_region = MemoryRegion::new(PhysAddr::null(), 640 * 1024);
        invalidate_boot_memory_region(config, stage2_region)?;
    }

    if config.invalidate_boot_data() {
        let kernel_elf_size =
            launch_info.kernel_elf_stage2_virt_end - launch_info.kernel_elf_stage2_virt_start;
        let kernel_elf_region = MemoryRegion::new(
            PhysAddr::new(launch_info.kernel_elf_stage2_virt_start.try_into().unwrap()),
            kernel_elf_size.try_into().unwrap(),
        );
        invalidate_boot_memory_region(config, kernel_elf_region)?;

        let kernel_fs_size = launch_info.kernel_fs_end - launch_info.kernel_fs_start;
        if kernel_fs_size > 0 {
            let kernel_fs_region = MemoryRegion::new(
                PhysAddr::new(launch_info.kernel_fs_start.try_into().unwrap()),
                kernel_fs_size.try_into().unwrap(),
            );
            invalidate_boot_memory_region(config, kernel_fs_region)?;
        }

        if launch_info.stage2_igvm_params_size > 0 {
            let igvm_params_region = MemoryRegion::new(
                PhysAddr::new(launch_info.stage2_igvm_params_phys_addr.try_into().unwrap()),
                launch_info.stage2_igvm_params_size as usize,
            );
            invalidate_boot_memory_region(config, igvm_params_region)?;
        }
    }

    Ok(())
}
