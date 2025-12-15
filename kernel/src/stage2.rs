// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

#![no_std]
#![no_main]

pub mod boot_stage2;
pub mod stage2_syms;

use bootdefs::kernel_launch::KernelLaunchInfo;
use bootdefs::kernel_launch::LOWMEM_END;
use bootdefs::kernel_launch::STAGE2_HEAP_END;
use bootdefs::kernel_launch::STAGE2_HEAP_START;
use bootdefs::kernel_launch::STAGE2_STACK;
use bootdefs::kernel_launch::STAGE2_STACK_END;
use bootdefs::kernel_launch::STAGE2_START;
use bootdefs::kernel_launch::Stage2LaunchInfo;
use bootdefs::platform::SvsmPlatformType;
use core::arch::asm;
use core::fmt::Debug;
use core::mem;
use core::mem::MaybeUninit;
use core::panic::PanicInfo;
use core::ptr;
use core::slice;
use cpuarch::snp_cpuid::SnpCpuidTable;
use elf::ElfError;
use svsm::address::{Address, PhysAddr, VirtAddr};
use svsm::boot_params::BootParams;
use svsm::console::install_console_logger;
use svsm::cpu::cpuid::{dump_cpuid_table, register_cpuid_table};
use svsm::cpu::flush_tlb_percpu;
use svsm::cpu::gdt::GLOBAL_GDT;
use svsm::cpu::idt::stage2::{early_idt_init, early_idt_init_no_ghcb};
use svsm::cpu::idt::{EARLY_IDT_ENTRIES, IDT, IdtEntry};
use svsm::cpu::percpu::{PERCPU_AREAS, PerCpu, this_cpu};
use svsm::debug::stacktrace::print_stack;
use svsm::error::SvsmError;
use svsm::mm::FixedAddressMappingRange;
use svsm::mm::PGTABLE_LVL3_IDX_PTE_SELFMAP;
use svsm::mm::STACK_GUARD_SIZE;
use svsm::mm::STACK_SIZE;
use svsm::mm::SVSM_GLOBAL_BASE;
use svsm::mm::SVSM_PERCPU_BASE;
use svsm::mm::SVSM_PERTASK_BASE;
use svsm::mm::alloc::{AllocError, memory_info, print_memory_info, root_mem_init};
use svsm::mm::init_kernel_mapping_info;
use svsm::mm::pagetable::PTEntry;
use svsm::mm::pagetable::PTEntryFlags;
use svsm::mm::pagetable::PageTable;
use svsm::mm::pagetable::make_private_address;
use svsm::mm::pagetable::paging_init;
use svsm::mm::validate::validate_mapped_region;
use svsm::platform;
use svsm::platform::{
    PageStateChangeOp, PageValidateOp, Stage2PlatformCell, SvsmPlatform, SvsmPlatformCell,
    init_platform_type,
};
use svsm::types::{PAGE_SIZE, PageSize};
use svsm::utils::{MemoryRegion, round_to_pages, zero_mem_region};

use elf::Elf64File;
use release::COCONUT_VERSION;

unsafe extern "C" {
    static mut pgtable: PageTable;
}

pub struct KernelHeap<'a> {
    local_virt_base: VirtAddr,
    virt_base: Option<VirtAddr>,
    phys_base: PhysAddr,
    usable_pages: usize,
    page_count: usize,
    next_free: usize,
    platform: &'a dyn SvsmPlatform,
    boot_params: &'a BootParams<'a>,
}

// The Debug trait is never actually needed for the kernel heap, but not
// including it generates a compile error.  Implement Debug with skeletal
// methods just to silence the errors.
impl Debug for KernelHeap<'_> {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        todo!()
    }
}

impl<'a> KernelHeap<'a> {
    pub fn create(
        prange: MemoryRegion<PhysAddr>,
        platform: &'a dyn SvsmPlatform,
        boot_params: &'a BootParams<'a>,
    ) -> Self {
        let reserve_pages = boot_params.vmsa_in_kernel_range() as usize;
        let page_count = prange.len() / PAGE_SIZE;
        Self {
            // The kernel heap is always mapped in the stage2 address space
            // at the base of the per-task address region, since this cannot
            // conflict with the global kernel region.
            local_virt_base: SVSM_PERTASK_BASE,
            virt_base: None,
            phys_base: prange.start(),
            page_count,
            usable_pages: page_count - reserve_pages,
            next_free: 0,
            platform,
            boot_params,
        }
    }

    pub fn virt_base(&self) -> Option<VirtAddr> {
        self.virt_base
    }

    pub fn phys_base(&self) -> PhysAddr {
        self.phys_base
    }

    pub fn page_count(&self) -> usize {
        self.page_count
    }

    pub fn next_free(&self) -> usize {
        self.next_free
    }

    pub fn phys_to_virt(&self, paddr: PhysAddr) -> VirtAddr {
        let offset = paddr - self.phys_base;
        assert!(offset < (self.page_count * PAGE_SIZE));

        // If the base virtual address has been set, then use it; otherwise
        // use the virtual address of the local mapping.
        self.virt_base.unwrap_or(self.local_virt_base) + offset
    }

    pub fn remap_memory(
        &mut self,
        vaddr: VirtAddr,
        page_tables: &mut KernelPageTables<'_>,
    ) -> Result<(), SvsmError> {
        // Map the heap physical memory span at the requested address in the
        // kernel page tables.  All memory has already been validated, so only
        // page table mapping is required.
        let flags = PTEntryFlags::data();
        for index in 0..self.page_count {
            let offset = index * PAGE_SIZE;
            page_tables.map_page(
                vaddr + offset,
                make_private_address(self.phys_base + offset),
                flags,
                self,
            )?;
        }

        // Record the new base virtual address of the heap.
        self.virt_base = Some(vaddr);

        Ok(())
    }

    pub fn allocate(&mut self, size: usize) -> Result<(VirtAddr, PhysAddr), SvsmError> {
        let page_count = round_to_pages(size);
        self.allocate_pages(page_count)
    }

    pub fn allocate_zeroed(&mut self, size: usize) -> Result<(VirtAddr, PhysAddr), SvsmError> {
        let (vaddr, paddr) = self.allocate(size)?;
        // SAFETY: the virtual address just allocated is known to map a new
        // allocation of the specified size, so it can be accessed for
        // zeroing.
        unsafe {
            ptr::write_bytes(vaddr.as_mut_ptr::<u8>(), 0, size);
        }
        Ok((vaddr, paddr))
    }

    pub fn allocate_pages(&mut self, page_count: usize) -> Result<(VirtAddr, PhysAddr), SvsmError> {
        // Verify that this allocation will not overflow the heap.
        let next_free = self.next_free + page_count;
        if next_free > self.usable_pages {
            return Err(AllocError::OutOfMemory.into());
        }

        // Calculate the allocation base based on the current position within
        // the heap.  If no heap virtual address has been configured yet,
        // then report a virtual address based on the local mapping.
        let offset = self.next_free * PAGE_SIZE;
        let virt_base = self.virt_base.unwrap_or(self.local_virt_base);
        let virt_addr = virt_base + offset;
        let phys_addr = self.phys_base + offset;

        // Heap pages are not validated until they are first allocated, so
        // validate them now.
        // SAFETY: the pages are being allocated for the first time here so
        // they cannot have been validated earlier.
        unsafe {
            validate_mapped_region(
                self.platform,
                self.boot_params,
                MemoryRegion::new(virt_addr, page_count * PAGE_SIZE),
            )?;
        }

        // Move the allocation cursor beyond this allocation.
        self.next_free = next_free;
        Ok((virt_addr, phys_addr))
    }
}

#[derive(Debug)]
pub struct KernelPageTablePage<'a> {
    entries: &'a mut [PTEntry],
}

impl KernelPageTablePage<'_> {
    /// # Safety
    /// The caller is required to supply a virtual address that is known to map
    /// a full page of page table or page directory entries.
    unsafe fn new(vaddr: VirtAddr) -> Self {
        // SAFETY: the caller ensures the correctness of the virtual address.
        let entries = unsafe {
            let pte_ptr = vaddr.as_mut_ptr::<PTEntry>();
            slice::from_raw_parts_mut(pte_ptr, svsm::mm::pagetable::ENTRY_COUNT)
        };
        Self { entries }
    }

    fn entry_mut(&mut self, index: usize) -> &mut PTEntry {
        &mut self.entries[index]
    }
}

#[derive(Debug)]
pub struct KernelPageTables<'a> {
    root_paddr: PhysAddr,
    lvl3_idx: usize,
    lvl2_idx: usize,
    pd_page: KernelPageTablePage<'a>,
    pt_page: Option<KernelPageTablePage<'a>>,
    pde_index: Option<usize>,
}

impl KernelPageTables<'_> {
    fn root(&self) -> PhysAddr {
        self.root_paddr
    }

    fn map_page(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        flags: PTEntryFlags,
        kernel_heap: &mut KernelHeap<'_>,
    ) -> Result<(), SvsmError> {
        // The virtual address must fall within the first 1 GB of the kernel
        // address range.
        assert_eq!(vaddr.to_pgtbl_idx::<3>(), self.lvl3_idx);
        assert_eq!(vaddr.to_pgtbl_idx::<2>(), self.lvl2_idx);

        // Release the reference to the currently mapped page table page if
        // this address falls within a different page table page.
        let pde_index = vaddr.to_pgtbl_idx::<1>();
        if let Some(mapped_pde_index) = self.pde_index {
            if pde_index != mapped_pde_index {
                self.pde_index = None;
                self.pt_page = None;
            }
        }

        // Map the correct page table page if it is not already mapped.
        if self.pt_page.is_none() {
            // If this page table page has not yet been allocated, then
            // allocate it now.  Otherwise, obtain a mapping to the
            // page that was previously allocated.
            let entry = self.pd_page.entry_mut(pde_index);
            let pt_page = if entry.present() {
                let pt_addr = kernel_heap.phys_to_virt(entry.address());
                // SAFETY: the virtual address here is calculated using a
                // physical address that was allocated earlier as a page table
                // page (and is therefore correct) and is translated to a
                // virtual address using an offset that was captured when the
                // heap was initialized, making it an accurate translation.
                unsafe { KernelPageTablePage::new(pt_addr) }
            } else {
                // If the entry is not present, it must be empty.
                assert_eq!(entry.raw(), 0);
                let (pt_vaddr, pt_paddr) = kernel_heap.allocate_zeroed(PAGE_SIZE)?;
                let pxe_flags =
                    PTEntryFlags::PRESENT | PTEntryFlags::WRITABLE | PTEntryFlags::ACCESSED;
                entry.set_unrestricted(make_private_address(pt_paddr), pxe_flags);

                // SAFETY: the virtual address corresponds to a newly allocated
                // page table page so it can safely be used here.
                unsafe { KernelPageTablePage::new(pt_vaddr) }
            };

            self.pde_index = Some(pde_index);
            self.pt_page = Some(pt_page);
        }

        let pt_page = self.pt_page.as_mut().unwrap();

        // Find the page table entry that will be populated.  It must already
        // be empty.
        let entry = pt_page.entry_mut(vaddr.to_pgtbl_idx::<0>());
        assert_eq!(entry.raw(), 0);
        entry.set_unrestricted(make_private_address(paddr), flags);

        Ok(())
    }

    fn map_and_validate(
        &mut self,
        vregion: MemoryRegion<VirtAddr>,
        phys_addr: PhysAddr,
        flags: PTEntryFlags,
        kernel_heap: &mut KernelHeap<'_>,
        platform: &dyn SvsmPlatform,
        boot_params: &BootParams<'_>,
    ) -> Result<(), SvsmError> {
        // Loop over each page in the region and map it into the page tables.
        for addr in vregion.iter_pages(PageSize::Regular) {
            let offset = addr - vregion.start();
            self.map_page(addr, phys_addr + offset, flags, kernel_heap)?;
        }

        if boot_params.page_state_change_required() {
            platform.page_state_change(
                MemoryRegion::new(phys_addr, vregion.len()),
                PageSize::Huge,
                PageStateChangeOp::Private,
            )?;
        }

        // SAFETY: the page table mapping operation above can only succeed if
        // each address is in the kernel address space and has been mapped for
        // the first time.  This guarantees that the virtual address region is
        // not already in use and thus can safely be validated here
        unsafe {
            platform.validate_virtual_page_range(vregion, PageValidateOp::Validate)?;
        }

        Ok(())
    }
}

fn setup_kernel_page_tables<'a>(
    heap: &mut KernelHeap<'_>,
) -> Result<KernelPageTables<'a>, SvsmError> {
    // Allocate a new page from the kernel heap to use as the paging root for
    // the kernel.
    let (paging_root_vaddr, paging_root_paddr) = heap.allocate_zeroed(PAGE_SIZE)?;

    // SAFETY: the allocated virtual address is known to be usable as a page
    // table page.
    let mut paging_root = unsafe { KernelPageTablePage::new(paging_root_vaddr) };
    // Set the PML4E for the self-map entry in the kernel paging root.
    let pxe_flags = PTEntryFlags::PRESENT | PTEntryFlags::WRITABLE | PTEntryFlags::ACCESSED;
    paging_root
        .entry_mut(PGTABLE_LVL3_IDX_PTE_SELFMAP)
        .set_unrestricted(
            make_private_address(paging_root_paddr),
            PTEntryFlags::task_data(),
        );

    // Allocate a new page to use as the page directory table page for the
    // kernel address space.
    let (pdpt_vaddr, pdpt_paddr) = heap.allocate_zeroed(PAGE_SIZE)?;
    // SAFETY: the allocated virtual address is known to be usable as a page
    // table page.
    let mut pdpt = unsafe { KernelPageTablePage::new(pdpt_vaddr) };

    // Set the correct PML4E in the kernel paging root to point to the page
    // directory page.
    let pml4e_index = SVSM_GLOBAL_BASE.to_pgtbl_idx::<3>();
    let pml4e = paging_root.entry_mut(pml4e_index);
    pml4e.set_unrestricted(make_private_address(pdpt_paddr), pxe_flags);

    // Set the PML4E in the current page table as well so the
    // kernel address space is also visible in the current address space.
    // SAFETY: the physical address of the current paging root is known to be
    // identity-mapped in the current address space and therefore that address
    // can be used to obtain a page table view.
    let mut current_paging_root = unsafe {
        let vaddr = VirtAddr::new(this_cpu().get_pgtable().cr3_value().bits());
        KernelPageTablePage::new(vaddr)
    };
    *current_paging_root.entry_mut(pml4e_index) = *pml4e;

    // Allocate a new page to use as a page directory table page.  This will
    // span 1 GB of address space, which is the maximum that will ever be
    // addressible during stage 2 execution.
    let (pdt_vaddr, pdt_paddr) = heap.allocate_zeroed(PAGE_SIZE)?;
    // SAFETY: the allocated virtual address is known to be usable as a page
    // table page.
    let pdt = unsafe { KernelPageTablePage::new(pdt_vaddr) };

    // Set the correct PDPE in the parent page.
    let pdt_index = SVSM_GLOBAL_BASE.to_pgtbl_idx::<2>();
    pdpt.entry_mut(pdt_index)
        .set_unrestricted(make_private_address(pdt_paddr), pxe_flags);

    Ok(KernelPageTables::<'a> {
        lvl3_idx: pml4e_index,
        lvl2_idx: pdt_index,
        root_paddr: paging_root_paddr,
        pd_page: pdt,
        pt_page: None,
        pde_index: None,
    })
}

fn setup_stage2_allocator(heap_start: u64, heap_end: u64) {
    let vstart = VirtAddr::from(heap_start);
    let vend = VirtAddr::from(heap_end);
    let pstart = PhysAddr::from(vstart.bits()); // Identity mapping
    let nr_pages = (vend - vstart) / PAGE_SIZE;

    root_mem_init(pstart, vstart, nr_pages, 0);
}

fn init_percpu(platform: &mut dyn SvsmPlatform) -> Result<(), SvsmError> {
    // SAFETY: this is the first CPU, so there can be no other dependencies
    // on multi-threaded access to the per-cpu areas.
    let percpu_shared = unsafe { PERCPU_AREAS.create_new(0) };
    let bsp_percpu = PerCpu::alloc(percpu_shared)?;
    bsp_percpu.set_current_stack(MemoryRegion::from_addresses(
        VirtAddr::from(STAGE2_STACK_END as u64),
        VirtAddr::from(STAGE2_STACK as u64),
    ));
    // SAFETY: pgtable is properly aligned and is never freed within the
    // lifetime of stage2. We go through a raw pointer to promote it to a
    // static mut. Only the BSP is able to get a reference to it so no
    // aliasing can occur.
    let init_pgtable = unsafe { (&raw mut pgtable).as_mut().unwrap() };
    bsp_percpu.set_pgtable(init_pgtable);
    bsp_percpu.map_self_stage2()?;
    platform.setup_guest_host_comm(bsp_percpu, true);
    Ok(())
}

/// Release all resources in the `PerCpu` instance associated with the current
/// CPU.
///
/// # Safety
///
/// The caller must ensure that the `PerCpu` is never used again.
unsafe fn shutdown_percpu() {
    let ptr = SVSM_PERCPU_BASE.as_mut_ptr::<PerCpu>();
    // SAFETY: ptr is properly aligned but the caller must ensure the PerCpu
    // structure is valid and not aliased.
    unsafe {
        core::ptr::drop_in_place(ptr);
    }
    // SAFETY: pgtable is properly aligned and is never freed within the
    // lifetime of stage2. We go through a raw pointer to promote it to a
    // static mut. Only the BSP is able to get a reference to it so no
    // aliasing can occur.
    let init_pgtable = unsafe { (&raw mut pgtable).as_mut().unwrap() };
    init_pgtable.unmap_4k(SVSM_PERCPU_BASE);
    flush_tlb_percpu();
}

// SAFETY: the caller must guarantee that the IDT specified here will remain
// in scope until a new IDT is loaded.
unsafe fn setup_env(
    boot_params: &BootParams<'_>,
    platform: &mut dyn SvsmPlatform,
    launch_info: &Stage2LaunchInfo,
    cpuid_vaddr: Option<VirtAddr>,
    idt: &mut IDT<'_>,
) {
    GLOBAL_GDT.load_selectors();
    // SAFETY: the caller guarantees that the lifetime of this IDT is suitable.
    unsafe {
        early_idt_init_no_ghcb(idt);
    }

    let debug_serial_port = boot_params.debug_serial_port();
    install_console_logger("Stage2").expect("Console logger already initialized");
    platform
        .env_setup(debug_serial_port, launch_info.vtom.try_into().unwrap())
        .expect("Early environment setup failed");

    let kernel_mapping = FixedAddressMappingRange::new(
        VirtAddr::from(u64::from(STAGE2_START)),
        VirtAddr::from(u64::from(launch_info.stage2_end)),
        PhysAddr::from(u64::from(STAGE2_START)),
    );

    if let Some(cpuid_addr) = cpuid_vaddr {
        // SAFETY: the CPUID page address specified in the launch info was
        // mapped by the loader, which promises to supply a correctly formed
        // CPUID page at that address.
        let cpuid_page = unsafe { &*cpuid_addr.as_ptr::<SnpCpuidTable>() };
        register_cpuid_table(cpuid_page);
    }

    paging_init(platform, true).expect("Failed to initialize early paging");

    // Use the low 640 KB of memory as the heap.
    let lowmem_region =
        MemoryRegion::from_addresses(VirtAddr::from(0u64), VirtAddr::from(u64::from(LOWMEM_END)));
    let heap_mapping = FixedAddressMappingRange::new(
        lowmem_region.start(),
        lowmem_region.end(),
        PhysAddr::from(0u64),
    );
    init_kernel_mapping_info(kernel_mapping, Some(heap_mapping));

    // Now that the heap virtual-to-physical mapping has been established,
    // validate the first 640 KB of memory so it can be used if necessary.
    // SAFETY: the low memory region is known not to overlap any memory in use.
    unsafe {
        platform
            .validate_low_memory(lowmem_region.end().into())
            .expect("failed to validate low 640 KB");
    }

    // Configure the heap.
    setup_stage2_allocator(STAGE2_HEAP_START.into(), STAGE2_HEAP_END.into());

    init_percpu(platform).expect("Failed to initialize per-cpu area");

    // Init IDT again with handlers requiring GHCB (eg. #VC handler)
    // Must be done after init_percpu() to catch early #PFs
    //
    // SAFETY: the caller guarantees that the lifetime of this IDT is suitable.
    unsafe {
        early_idt_init(idt);
    }

    // Complete initializtion of the platform.  After that point, the console
    // will be fully working and any unsupported configuration can be properly
    // reported.
    platform
        .env_setup_late(debug_serial_port)
        .expect("Late environment setup failed");

    if cpuid_vaddr.is_some() {
        dump_cpuid_table();
    }
}

/// # Safety
/// The caller is required to ensure that the source virtual address, if
/// present, maps to a valid page of data that can be copied.
unsafe fn copy_page_to_kernel(
    src_vaddr: Option<VirtAddr>,
    kernel_heap: &mut KernelHeap<'_>,
) -> Result<VirtAddr, SvsmError> {
    let (dst_vaddr, _) = kernel_heap.allocate(PAGE_SIZE)?;
    if let Some(vaddr) = src_vaddr {
        // SAFETY: the caller takes responsibility for the correctness of the
        // source address, and the destination address is known to be correct
        // because it was just allocated as a full page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                vaddr.as_ptr::<u8>(),
                dst_vaddr.as_mut_ptr::<u8>(),
                PAGE_SIZE,
            );
        }
    }

    Ok(dst_vaddr)
}

/// Map the specified virtual memory region at the given physical address.
/// This will fail if the caller specifies a virtual address region that is
/// already mapped.
fn map_page_range(vregion: MemoryRegion<VirtAddr>, paddr: PhysAddr) -> Result<(), SvsmError> {
    let flags = PTEntryFlags::PRESENT
        | PTEntryFlags::WRITABLE
        | PTEntryFlags::ACCESSED
        | PTEntryFlags::DIRTY;

    let mut pgtbl = this_cpu().get_pgtable();
    pgtbl.map_region(vregion, paddr, flags)?;

    Ok(())
}

/// Loads a single ELF segment and returns its virtual memory region.
/// # Safety
/// The caller is required to supply an appropriate virtual address for this
/// ELF segment.
fn load_elf_segment(
    segment: elf::Elf64ImageLoadSegment<'_>,
    paddr: PhysAddr,
    page_tables: &mut KernelPageTables<'_>,
    kernel_heap: &mut KernelHeap<'_>,
    platform: &dyn SvsmPlatform,
    boot_params: &BootParams<'_>,
) -> Result<MemoryRegion<VirtAddr>, SvsmError> {
    // Find the segment's bounds
    let segment_start = VirtAddr::from(segment.vaddr_range.vaddr_begin);
    let segment_end = VirtAddr::from(segment.vaddr_range.vaddr_end).page_align_up();
    let segment_len = segment_end - segment_start;
    let segment_region = MemoryRegion::new(segment_start, segment_len);

    // All ELF segments should be aligned to the page size. If not, there's
    // the risk of pvalidating a page twice, bail out if so. Note that the
    // ELF reading code had already verified that the individual segments,
    // with bounds specified as in the ELF file, are non-overlapping.
    if !segment_start.is_page_aligned() {
        return Err(SvsmError::Elf(ElfError::UnalignedSegmentAddress));
    }

    // Calculate the correct page table flags based on this segment's
    // characteristics.
    let flags = if segment.flags.contains(elf::Elf64PhdrFlags::EXECUTE) {
        PTEntryFlags::exec()
    } else if segment.flags.contains(elf::Elf64PhdrFlags::WRITE) {
        PTEntryFlags::data()
    } else {
        PTEntryFlags::data_ro()
    };

    // Map and validate the segment at the next contiguous physical address
    page_tables.map_and_validate(
        segment_region,
        paddr,
        flags,
        kernel_heap,
        platform,
        boot_params,
    )?;

    // Copy the segment contents and pad with zeroes
    // SAFETY: the call to map_and_validate above will prove the correctness of
    // the kernel address range.
    let segment_buf =
        unsafe { slice::from_raw_parts_mut(segment_start.as_mut_ptr::<u8>(), segment_len) };
    let contents_len = segment.file_contents.len();
    segment_buf[..contents_len].copy_from_slice(segment.file_contents);
    segment_buf[contents_len..].fill(0);

    Ok(segment_region)
}

/// Calculates the number of physical pages required to load an ELF file.
fn count_elf_pages(elf: &Elf64File<'_>) -> usize {
    // Enumerate the segments of this ELF file to count the total amount of
    // physical memory required.
    let mut page_count: usize = 0;
    let vaddr_alloc_info = elf.image_load_vaddr_alloc_info();
    let vaddr_alloc_base = vaddr_alloc_info.range.vaddr_begin;
    for segment in elf.image_load_segment_iter(vaddr_alloc_base) {
        let segment_size =
            (segment.vaddr_range.vaddr_end - segment.vaddr_range.vaddr_begin) as usize;
        page_count += round_to_pages(segment_size);
    }

    page_count
}

fn read_kernel_elf(launch_info: &Stage2LaunchInfo) -> Result<elf::Elf64File<'static>, ElfError> {
    // Find the bounds of the kernel ELF and load it into the ELF parser
    let elf_start = PhysAddr::from(launch_info.kernel_elf_start as u64);
    let elf_end = PhysAddr::from(launch_info.kernel_elf_end as u64);
    let elf_len = elf_end - elf_start;
    // SAFETY: the base address of the ELF image was selected by the loader and
    // is known not to conflict with any other virtual address mappings.
    let bytes = unsafe { slice::from_raw_parts(elf_start.bits() as *const u8, elf_len) };
    elf::Elf64File::read(bytes)
}

/// Loads the kernel ELF and returns the virtual memory region where it
/// resides, as well as its entry point. Updates the used physical memory
/// region accordingly.
fn load_kernel_elf(
    elf: &Elf64File<'_>,
    paddr_base: PhysAddr,
    expected_page_count: usize,
    page_tables: &mut KernelPageTables<'_>,
    kernel_heap: &mut KernelHeap<'_>,
    platform: &dyn SvsmPlatform,
    boot_params: &BootParams<'_>,
) -> Result<(VirtAddr, MemoryRegion<VirtAddr>), SvsmError> {
    let vaddr_alloc_info = elf.image_load_vaddr_alloc_info();
    let vaddr_alloc_base = vaddr_alloc_info.range.vaddr_begin;

    // Map, validate and populate the SVSM kernel ELF's PT_LOAD segments. The
    // segments' virtual address range might not necessarily be contiguous,
    // track their total extent along the way. Physical memory is successively
    // being taken from the physical memory region, the remaining space will be
    // available as heap space for the SVSM kernel. Remember the end of all
    // physical memory occupied by the loaded ELF image.
    let mut load_virt_start = None;
    let mut load_virt_end = VirtAddr::null();
    let mut phys_addr = paddr_base;
    for segment in elf.image_load_segment_iter(vaddr_alloc_base) {
        let region = load_elf_segment(
            segment,
            phys_addr,
            page_tables,
            kernel_heap,
            platform,
            boot_params,
        )?;
        // Remember the mapping range's lower and upper bounds to pass it on
        // the kernel later. Note that the segments are being iterated over
        // here in increasing load order.
        if load_virt_start.is_none() {
            load_virt_start = Some(region.start());
        }
        load_virt_end = region.end();

        // Update to the next contiguous physical address
        phys_addr = phys_addr + region.len();
    }

    // The amount of physical memory actually consumed must match the amount
    // of memory that was set aside.
    assert_eq!(phys_addr - paddr_base, expected_page_count * PAGE_SIZE);

    let Some(load_virt_start) = load_virt_start else {
        log::error!("No loadable segment found in kernel ELF");
        return Err(SvsmError::Mem);
    };

    // Apply relocations, if any
    if let Some(dyn_relocs) =
        elf.apply_dyn_relas(elf::Elf64X86RelocProcessor::new(), vaddr_alloc_base)?
    {
        for reloc in dyn_relocs {
            let Some(reloc) = reloc? else {
                continue;
            };
            // SAFETY: the relocation address is known to be correct. The ELF loader rejects
            // relocations that point outside a PT_LOAD segment.
            let dst = unsafe { slice::from_raw_parts_mut(reloc.dst as *mut u8, reloc.value_len) };
            let src = &reloc.value[..reloc.value_len];
            dst.copy_from_slice(src)
        }
    }

    let entry = VirtAddr::from(elf.get_entry(vaddr_alloc_base));
    let region = MemoryRegion::from_addresses(load_virt_start, load_virt_end);
    Ok((entry, region))
}

/// Loads the boot parameters.  Returns the virtual and physical memory regions
/// containing the loaded data.
/// # Safety
/// Ther caller is required to specify the correct virtual address for the
/// kernel virtual region.
fn load_igvm_params(
    kernel_heap: &mut KernelHeap<'_>,
    boot_params: &BootParams<'_>,
    launch_info: &Stage2LaunchInfo,
) -> Result<VirtAddr, SvsmError> {
    let params_size = boot_params.size();

    // Allocate space in the kernel area to hold the parameters.
    let (vaddr, _) = kernel_heap.allocate(params_size)?;

    // Copy the contents over
    let src_addr = VirtAddr::from(launch_info.boot_params as u64);
    // SAFETY: the destination address came from the heap allocation above and
    // can be used safely. The source address specified in the launch info was
    // mapped by the loader, which promises to supply a correctly formed IGVM
    // parameter block.
    unsafe {
        vaddr
            .as_mut_ptr::<u8>()
            .copy_from_nonoverlapping(src_addr.as_ptr::<u8>(), params_size)
    };

    Ok(vaddr)
}

/// Maps any remaining memory between the end of the kernel image and the end
/// of the allocated kernel memory region as heap space. Exclude any memory
/// reserved by the configuration.
///
/// # Panics
///
/// Panics if the allocated kernel region (`kernel_region`) is not sufficient
/// to host the memory required by the loaded kernel (`kernel_page_count`)
/// plus memory reserved for configuration.
fn prepare_heap<'a>(
    kernel_region: MemoryRegion<PhysAddr>,
    kernel_page_count: usize,
    platform: &'a dyn SvsmPlatform,
    boot_params: &'a BootParams<'a>,
) -> Result<KernelHeap<'a>, SvsmError> {
    let kernel_size = kernel_page_count * PAGE_SIZE;
    let heap_pstart = kernel_region.start() + kernel_size;

    let heap_size = kernel_region
        .end()
        .checked_sub(heap_pstart.into())
        .and_then(|r| r.checked_sub(kernel_size))
        .expect("Insufficient physical space for kernel image")
        .into();

    let heap_pregion = MemoryRegion::new(heap_pstart, heap_size);
    let heap = KernelHeap::create(heap_pregion, platform, boot_params);
    let heap_vregion = MemoryRegion::new(heap.local_virt_base, heap_size);

    // Map the heap region into the page tables but do not validate it.
    // Validation will be performed later, either as the pages are allocated or
    // when the kernel starts.
    map_page_range(heap_vregion, heap_pregion.start())?;

    Ok(heap)
}

#[unsafe(no_mangle)]
pub extern "C" fn stage2_main(launch_info: &Stage2LaunchInfo) -> ! {
    let platform_type = SvsmPlatformType::from(launch_info.platform_type);

    init_platform_type(platform_type);
    let mut platform_cell = SvsmPlatformCell::new(true);
    let platform = platform_cell.platform_mut();
    let stage2_platform_cell = Stage2PlatformCell::new(platform_type);
    let stage2_platform = stage2_platform_cell.platform();

    // SAFETY: the address in the launch info is known to be correct.
    let boot_params = unsafe { BootParams::new(VirtAddr::from(launch_info.boot_params as u64)) }
        .expect("Failed to get boot parameters");

    // Set up space for an early IDT.  This will remain in scope as long as
    // stage2 is in memory.
    let mut early_idt = [IdtEntry::no_handler(); EARLY_IDT_ENTRIES];
    let mut idt = IDT::new(&mut early_idt);

    // Get a reference to the CPUID page if this platform requires it.
    let cpuid_page = stage2_platform.get_cpuid_page(launch_info);

    // SAFETY: the IDT here will remain in scope until the full IDT is
    // initialized later, and thus can safely be used as the early IDT.
    unsafe {
        setup_env(&boot_params, platform, launch_info, cpuid_page, &mut idt);
    }

    // Get the available physical memory region for the kernel
    let kernel_region = boot_params
        .find_kernel_region()
        .expect("Failed to find memory region for SVSM kernel");

    log::info!("SVSM memory region: {kernel_region:#018x}");

    // Load first the kernel ELF and update the loaded physical region
    let elf = read_kernel_elf(launch_info).expect("Failed to read kernel ELF");

    // Calculate the number of physical pages that will be consumed when the
    // ELF is loaded.
    let elf_page_count = count_elf_pages(&elf);

    // Create the page heap that will be used in the kernel region.  This is
    // the size of the kernel region minus the space used to hold the loaded
    // ELF image.
    let mut kernel_heap = prepare_heap(kernel_region, elf_page_count, platform, &boot_params)
        .expect("Could not create kernel heap");

    // Set up the paging root for the kernel page tables, which will be
    // allocated from the kernel heap.
    let mut kernel_page_tables =
        setup_kernel_page_tables(&mut kernel_heap).expect("Failed to configure kernel page tables");

    // Load the kernel ELF into the address space.
    let (kernel_entry, loaded_kernel_vregion) = load_kernel_elf(
        &elf,
        kernel_region.start(),
        elf_page_count,
        &mut kernel_page_tables,
        &mut kernel_heap,
        platform,
        &boot_params,
    )
    .expect("Failed to load kernel ELF");

    // Define the heap base address as the end of the kernel ELF plus a
    // guard area for a stack.
    let heap_base_vaddr = loaded_kernel_vregion.end() + STACK_GUARD_SIZE;

    // Map the heap into the kernel address space immediately following the
    // kernel image.
    kernel_heap
        .remap_memory(heap_base_vaddr, &mut kernel_page_tables)
        .expect("Failed to map kernel heap");

    // Allocate pages for an initial stack to be used in the kernel
    // environment.
    let (initial_stack_base, _) = kernel_heap
        .allocate(STACK_SIZE)
        .expect("Failed to allocate initial kernel stack");
    let initial_stack = initial_stack_base + STACK_SIZE;

    let (symtab, strtab) = stage2_syms::load_kernel_symbols(&elf, &mut kernel_heap);

    // Load the IGVM params, if present. Update loaded region accordingly.
    // SAFETY: The loaded kernel region was correctly calculated above and
    // is sized appropriately to include a copy of the IGVM parameters.
    let params_vaddr = load_igvm_params(&mut kernel_heap, &boot_params, launch_info)
        .expect("Failed to load IGVM params");

    // Copy the CPUID page into the kernel address space as required.
    // SAFETY: the CPUID address is assumed to have been correctly retrieved
    // from the launch info by the stage2 platform object.
    let kernel_cpuid_page = unsafe {
        copy_page_to_kernel(cpuid_page, &mut kernel_heap).expect("Failed to copy CPUID page")
    };

    // Determine whether this platforms uses a secrets pgae.
    let secrets_page = stage2_platform.get_secrets_page(launch_info);

    // Copy the secrets page into the kernel address space as required.
    // SAFETY: the secrets page address is assumed to have been correctly
    // configured in the stage2 image if it is present at all.
    let kernel_secrets_page = unsafe {
        let new_vaddr = copy_page_to_kernel(secrets_page, &mut kernel_heap)
            .expect("Failed to copy secrets page");
        if let Some(secrets_addr) = secrets_page {
            zero_mem_region(secrets_addr, secrets_addr + PAGE_SIZE);
        }
        new_vaddr
    };

    // Determine whether use of interrupts on the SVSM should be suppressed.
    // This is required when running SNP under KVM/QEMU.
    let suppress_svsm_interrupts = match platform_type {
        SvsmPlatformType::Snp => boot_params.suppress_svsm_interrupts_on_snp(),
        _ => false,
    };

    // Allocate memory in the kernel heap to hold the kernel launch parameters.
    let (launch_info_vaddr, _) = kernel_heap
        .allocate(mem::size_of::<KernelLaunchInfo>())
        .expect("Failed to allocate memory for kernel launch block");

    // Build the handover information describing the memory layout and hand
    // control to the SVSM kernel.
    let kernel_launch_info = KernelLaunchInfo {
        kernel_region_phys_start: u64::from(kernel_region.start()),
        kernel_region_phys_end: u64::from(kernel_region.end()),
        heap_area_phys_start: u64::from(kernel_heap.phys_base()),
        heap_area_virt_start: u64::from(kernel_heap.virt_base().unwrap()),
        heap_area_page_count: kernel_heap.page_count().try_into().unwrap(),
        heap_area_allocated: kernel_heap.next_free().try_into().unwrap(),
        kernel_region_virt_start: u64::from(loaded_kernel_vregion.start()),
        kernel_fs_start: u64::from(launch_info.kernel_fs_start),
        kernel_fs_end: u64::from(launch_info.kernel_fs_end),
        stage2_start: 0x800000u64,
        cpuid_page: u64::from(kernel_cpuid_page),
        secrets_page: u64::from(kernel_secrets_page),
        boot_params_virt_addr: u64::from(params_vaddr),
        kernel_symtab_start: symtab.start().as_ptr(),
        kernel_symtab_len: (symtab.len() / size_of::<bootdefs::symbols::KSym>()) as u64,
        kernel_strtab_start: strtab.start().as_ptr(),
        kernel_strtab_len: strtab.len() as u64,
        vtom: launch_info.vtom,
        debug_serial_port: boot_params.debug_serial_port(),
        use_alternate_injection: boot_params.use_alternate_injection(),
        kernel_page_table_vaddr: u64::from(kernel_heap.phys_to_virt(kernel_page_tables.root())),
        vmsa_in_kernel_heap: boot_params.vmsa_in_kernel_range(),
        suppress_svsm_interrupts,
    };

    // SAFETY: the virtual address of the allocated block is known to be usable
    // and is known to be uninitialized data which can be filled with the
    // computed launch information.
    unsafe {
        let kernel_launch_block =
            &mut *launch_info_vaddr.as_mut_ptr::<MaybeUninit<KernelLaunchInfo>>();
        kernel_launch_block.write(kernel_launch_info);
    };

    let mem_info = memory_info();
    print_memory_info(&mem_info);

    log::info!(
        "  kernel_region_phys_start = {:#018x}",
        kernel_region.start()
    );
    log::info!("  kernel_region_phys_end   = {:#018x}", kernel_region.end());
    log::info!(
        "  kernel_virtual_base      = {:#018x}",
        loaded_kernel_vregion.start()
    );

    log::info!("Starting SVSM kernel...");

    // SAFETY: the addreses used to invoke the kernel have been calculated
    // correctly for use in the assembly trampoline.
    unsafe {
        // Shut down the PerCpu instance
        shutdown_percpu();

        asm!("jmp *%rax",
             in("rax") u64::from(kernel_entry),
             in("rdi") u64::from(launch_info_vaddr),
             in("rsi") platform_type as u64,
             in("rdx") u64::from(initial_stack),
             in("rcx") u64::from(initial_stack_base),
             in("r8") u64::from(kernel_page_tables.root()),
             options(att_syntax))
    };

    unreachable!("Road ends here!");
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    log::error!("Panic! COCONUT-SVSM Version: {}", COCONUT_VERSION);
    log::error!("Info: {}", info);

    print_stack(3);

    platform::terminate();
}
