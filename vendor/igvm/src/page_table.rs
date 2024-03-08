// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Methods to construct page tables.

use crate::hv_defs::Vtl;
use range_map_vec::RangeMap;
use std::collections::BTreeMap;
use thiserror::Error;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

const X64_CR4_LA57: u64 = 0x0000000000001000; // 5-level paging enabled

const X64_PTE_PRESENT: u64 = 1;
const X64_PTE_READ_WRITE: u64 = 1 << 1;
const X64_PTE_ACCESSED: u64 = 1 << 5;
const X64_PTE_DIRTY: u64 = 1 << 6;
const X64_PTE_LARGE_PAGE: u64 = 1 << 7;

const PAGE_TABLE_ENTRY_COUNT: usize = 512;

const X64_PAGE_SHIFT: u64 = 12;
const X64_PTE_BITS: u64 = 9;

/// Number of bytes in a page for X64.
pub const X64_PAGE_SIZE: u64 = 4096;

/// Number of bytes in a large page for X64.
pub const X64_LARGE_PAGE_SIZE: u64 = 0x200000;

/// Number of bytes in a 1GB page for X64.
pub const X64_1GB_PAGE_SIZE: u64 = 0x40000000;

#[derive(Copy, Clone, PartialEq, Eq, AsBytes, FromBytes, FromZeroes)]
#[repr(transparent)]
pub struct PageTableEntry {
    entry: u64,
}

impl std::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageTableEntry")
            .field("entry", &self.entry)
            .field("is_present", &self.is_present())
            .field("is_large_page", &self.is_large_page())
            .field("gpa", &self.gpa())
            .finish()
    }
}

#[derive(Debug, Copy, Clone)]
pub enum PageTableEntryType {
    Leaf1GbPage(u64),
    Leaf2MbPage(u64),
    Leaf4kPage(u64),
    Pde(u64),
}

impl PageTableEntry {
    /// Set an AMD64 PDE to either represent a leaf 2MB page or PDE.
    /// This sets the PTE to preset, accessed, dirty, read write execute.
    pub fn set_entry(&mut self, entry_type: PageTableEntryType) {
        self.entry = X64_PTE_PRESENT | X64_PTE_ACCESSED | X64_PTE_READ_WRITE;

        match entry_type {
            PageTableEntryType::Leaf1GbPage(address) => {
                // Must be 1GB aligned.
                assert!(address % X64_1GB_PAGE_SIZE == 0);
                self.entry |= address;
                self.entry |= X64_PTE_LARGE_PAGE | X64_PTE_DIRTY;
            }
            PageTableEntryType::Leaf2MbPage(address) => {
                // Leaf entry, set like UEFI does for 2MB pages. Must be 2MB aligned.
                assert!(address % X64_LARGE_PAGE_SIZE == 0);
                self.entry |= address;
                self.entry |= X64_PTE_LARGE_PAGE | X64_PTE_DIRTY;
            }
            PageTableEntryType::Leaf4kPage(address) => {
                // Must be 4K aligned.
                assert!(address % X64_PAGE_SIZE == 0);
                self.entry |= address;
                self.entry |= X64_PTE_DIRTY;
            }
            PageTableEntryType::Pde(address) => {
                // Points to another pagetable.
                assert!(address % X64_PAGE_SIZE == 0);
                self.entry |= address;
            }
        }
    }

    pub fn is_present(&self) -> bool {
        self.entry & X64_PTE_PRESENT == X64_PTE_PRESENT
    }

    pub fn is_large_page(&self) -> bool {
        self.entry & X64_PTE_LARGE_PAGE == X64_PTE_LARGE_PAGE
    }

    pub fn gpa(&self) -> Option<u64> {
        if self.is_present() {
            // bits 51 to 12 describe the gpa of the next page table
            Some(self.entry & 0x000f_ffff_ffff_f000)
        } else {
            None
        }
    }

    pub fn set_addr(&mut self, addr: u64) {
        const VALID_BITS: u64 = 0x000f_ffff_ffff_f000;
        assert!(addr & !VALID_BITS == 0);

        // clear addr bits, set new addr
        self.entry &= !0x000f_ffff_ffff_f000;
        self.entry |= addr;
    }

    pub fn clear(&mut self) {
        self.entry = 0;
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, AsBytes, FromBytes, FromZeroes)]
pub struct PageTable {
    entries: [PageTableEntry; PAGE_TABLE_ENTRY_COUNT],
}

impl PageTable {
    // fn iter(&self) -> impl Iterator<Item = &PageTableEntry> {
    //     self.entries.iter()
    // }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut PageTableEntry> {
        self.entries.iter_mut()
    }

    /// Treat this page table as a page table of a given level, and locate the entry corresponding to a va.
    pub fn entry(&mut self, gva: u64, level: u8) -> &mut PageTableEntry {
        let index = get_amd64_pte_index(gva, level as u64) as usize;
        &mut self.entries[index]
    }
}

impl std::ops::Index<usize> for PageTable {
    type Output = PageTableEntry;

    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

impl std::ops::IndexMut<usize> for PageTable {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.entries[index]
    }
}

/// Get an AMD64 PTE index based on page table level.
fn get_amd64_pte_index(gva: u64, page_map_level: u64) -> u64 {
    let index = gva >> (X64_PAGE_SHIFT + page_map_level * X64_PTE_BITS);
    index & ((1 << X64_PTE_BITS) - 1)
}

fn flatten_page_table(page_table: Vec<PageTable>) -> Vec<u8> {
    let mut flat_tables = Vec::with_capacity(page_table.len() * X64_PAGE_SIZE as usize);
    for table in page_table {
        flat_tables.extend_from_slice(table.as_bytes());
    }

    flat_tables
}

/// Errors when building a relocated page table.
#[derive(Debug, Error)]
pub enum Error {
    #[error("page data length is not 4k")]
    PageDataLength,
    #[error("page data gpa not contained within builder region")]
    PageDataGpa,
    #[error("cr3 is not within the page table region")]
    Cr3,
    #[error("a relocation offset is not aligned to a page table mapping")]
    UnalignedOffset {
        va: u64,
        page_table_entry_mapping_size: u64,
        relocation_offset: i64,
    },
    #[error("page table region does not have enough free space to fix up page table")]
    NotEnoughFreeSpace,
}

/// Cpu state related to paging.
#[derive(Debug, Clone, Copy)]
pub struct CpuPagingState {
    pub cr3: u64,
    pub cr4: u64,
}

/// A builder class that rebuilds the page table specified by an
/// [`crate::IgvmInitializationHeader::PageTableRelocationRegion`].
#[derive(Debug, Clone)]
pub struct PageTableRelocationBuilder {
    /// Base gpa for the page table region.
    pub gpa: u64,
    /// Size in bytes of the page table region.
    pub size: u64,
    /// Used bytes in this page table region.
    pub used_size: u64,
    page_data: Vec<u8>,
    /// Vp index for cpu state to be queried when rebuilding the page table.
    pub vp_index: u16,
    /// Vtl for cpu state to be queried when rebuilding the page table.
    pub vtl: Vtl,
}

impl PageTableRelocationBuilder {
    pub fn new(gpa: u64, size: u64, used_size: u64, vp_index: u16, vtl: Vtl) -> Self {
        assert!(used_size <= size);

        PageTableRelocationBuilder {
            gpa,
            size,
            used_size,
            page_data: vec![0; used_size as usize],
            vp_index,
            vtl,
        }
    }

    /// Set pre existing page table data from a
    /// [`crate::IgvmDirectiveHeader::PageData`]. `gpa` contains the unrelocated
    /// gpa stored within the directive header.
    pub fn set_page_data(&mut self, gpa: u64, data: &[u8]) -> Result<(), Error> {
        // Empty data is valid, as this would mean a page of zeros.
        if data.is_empty() {
            return Ok(());
        }

        // data must be 4K if it contains non-zero data.
        if data.len() != X64_PAGE_SIZE as usize {
            return Err(Error::PageDataLength);
        }

        if !self.contains(gpa) {
            return Err(Error::PageDataGpa);
        }

        let start = (gpa - self.gpa) as usize;
        let end = start + X64_PAGE_SIZE as usize;
        self.page_data[start..end].copy_from_slice(data);

        Ok(())
    }

    pub fn contains(&self, gpa: u64) -> bool {
        let end = self.gpa + self.size;
        gpa >= self.gpa && gpa < end
    }

    /// Recursively walk the page table and fix any PDE entries based on
    /// `table_reloc_offest`. Puts entries in regions that have been relocated
    /// that require moving to a different PTE entry `entry_map` and clears the
    /// original entry.
    fn recurse_fixup(
        &self,
        table_reloc_offset: i64,
        page_tables: &mut Vec<PageTable>,
        entry_map: &mut BTreeMap<u64, (u8, PageTableEntry)>,
        relocation_offsets: &RangeMap<u64, i64>,
        table_index: usize,
        level: u8,
        mut current_va: u64,
    ) -> Result<(), Error> {
        let mut entry_index = 0;

        /// Information needed to recursively traverse the next level down page
        /// table.
        struct NextTableInfo {
            table_index: usize,
            current_va: u64,
        }

        while entry_index < 512 {
            let table = &mut page_tables[table_index];
            let mut recurse_table = None;

            // Walk each page table entry that hasn't yet been walked.
            for entry in table.iter_mut().skip(entry_index) {
                entry_index += 1;
                let mapping_size = Self::mapping_size(level);
                let entry_va = current_va;
                current_va += mapping_size;

                if entry.is_present() {
                    // First check if this is a PDE entry or not. PDE entries
                    // require recursing further.
                    let is_pde_entry = match level {
                        3 => true, // PML4E entries are always PDEs
                        2 | 1 => !entry.is_large_page(),
                        0 => false,
                        _ => unreachable!(),
                    };

                    if is_pde_entry {
                        let old_gpa = entry.gpa().expect("entry is present");

                        // Fixup this PDE entry if it lies within the page table
                        // region, then calculate the next table_index and
                        // recurse.
                        if let Some(index) = self.calculate_page_table_index(old_gpa) {
                            let new_gpa = Self::relocate_address(old_gpa, table_reloc_offset);
                            entry.set_addr(new_gpa);
                            recurse_table = Some(NextTableInfo {
                                table_index: index,
                                current_va: entry_va,
                            });
                            break;
                        } else {
                            // This PDE entry refers to a page table outside of
                            // the page table relocation region, leave it as is.
                            continue;
                        }
                    }

                    // This entry is a leaf entry that maps address space.
                    // Determine if the region it maps was relocated outside of
                    // the region mapped by this leaf entry.
                    let start = entry_va;
                    let end = entry_va + mapping_size - 1;
                    if let Some(offset) = relocation_offsets.get_range(start..=end) {
                        // Determine if we need to actually move this page table
                        // entry. If the relocation happened within the mapped
                        // region, there's no need to move the entry.
                        if offset.unsigned_abs() < mapping_size {
                            continue;
                        }

                        let new_va = Self::relocate_address(entry_va, *offset);

                        // If the new_va is not aligned to the mapping size,
                        // this relocation and IGVM file is invalid. Bail out
                        // now.
                        if new_va % mapping_size != 0 {
                            return Err(Error::UnalignedOffset {
                                va: entry_va,
                                page_table_entry_mapping_size: mapping_size,
                                relocation_offset: *offset,
                            });
                        }

                        let mut new_entry = *entry;
                        new_entry.set_addr(new_va);
                        assert!(entry_map.insert(new_va, (level, new_entry)).is_none());

                        entry.clear();
                    } else {
                        // This entry maps a region that's not relocated, so
                        // leave it as is.
                    }
                }
            }

            match recurse_table {
                Some(info) => {
                    // Recurse to the next page table, to fixup any entries
                    // there.
                    self.recurse_fixup(
                        table_reloc_offset,
                        page_tables,
                        entry_map,
                        relocation_offsets,
                        info.table_index,
                        level - 1,
                        info.current_va,
                    )?;
                }
                None => {
                    // The only condition where we're not recursing is when
                    // we've processed all entries in this table.
                    assert!(entry_index == 512);
                }
            }
        }

        Ok(())
    }

    fn relocate_address(addr: u64, offset: i64) -> u64 {
        if offset >= 0 {
            addr + offset as u64
        } else {
            addr - (offset as u64)
        }
    }

    fn mapping_size(level: u8) -> u64 {
        const SIZE_512_GB: u64 = 0x8000000000;
        match level {
            3 => SIZE_512_GB,
            2 => X64_1GB_PAGE_SIZE,
            1 => X64_LARGE_PAGE_SIZE,
            0 => X64_PAGE_SIZE,
            _ => unreachable!(),
        }
    }

    fn calculate_page_table_index(&self, page_table_gpa: u64) -> Option<usize> {
        if self.contains(page_table_gpa) {
            Some(((page_table_gpa - self.gpa) / X64_PAGE_SIZE) as usize)
        } else {
            None
        }
    }

    fn calculate_page_table_addr(region_base_gpa: u64, page_table_index: usize) -> u64 {
        region_base_gpa + page_table_index as u64 * X64_PAGE_SIZE
    }

    /// Build the fixed up page table with the relocation offset for this page
    /// table region, and the relocation offsets used for other ranges to fix up
    /// page table entries.
    pub fn build(
        self,
        table_reloc_offset: i64,
        relocation_offsets: RangeMap<u64, i64>,
        paging_state: CpuPagingState,
    ) -> Result<Vec<u8>, Error> {
        assert_eq!(self.page_data.len() as u64, self.used_size);

        let CpuPagingState { cr3: old_cr3, cr4 } = paging_state;

        if cr4 & X64_CR4_LA57 == X64_CR4_LA57 {
            todo!("handle 5 level paging")
        }

        if !self.contains(old_cr3) {
            return Err(Error::Cr3);
        }

        // Create the initial page table based on the used_size of the region.
        let mut page_tables: Vec<PageTable> = self
            .page_data
            .as_slice()
            .chunks_exact(X64_PAGE_SIZE as usize)
            .map(|chunk| PageTable::read_from_prefix(chunk).expect("chunk size is correct"))
            .collect();

        // Map of PTEs to relocate. Maps new_va, (page table level, entry value)
        let mut entry_map: BTreeMap<u64, (u8, PageTableEntry)> = BTreeMap::new();

        // Walk the page table recursively, and fixup PDE entries while
        // bookkeping which entries need to be moved. Entries that need to be
        // moved will be fixed in pass 2, as additional page tables may need to
        // be allocated.
        self.recurse_fixup(
            table_reloc_offset,
            &mut page_tables,
            &mut entry_map,
            &relocation_offsets,
            self.calculate_page_table_index(old_cr3)
                .expect("region must contain cr3"),
            3,
            0,
        )?;

        let new_cr3 = Self::relocate_address(old_cr3, table_reloc_offset);

        // Add new tables based on how much additional free space exists in the region.
        let free_table_count = (self.size - self.used_size) / X64_PAGE_SIZE;
        let mut free_table_index = page_tables.len();

        for _ in 0..free_table_count {
            page_tables.push(PageTable::new_zeroed());
        }

        let page_table_len = page_tables.len();

        // Pass 2, set all entries that have needed relocation due to mapping
        // part of a relocatable region. Create a new instance of the page table
        // relocation builder that has the correct relocated region info, which
        // is used to calculate page table indices.
        let reloc_builder = PageTableRelocationBuilder {
            gpa: Self::relocate_address(self.gpa, table_reloc_offset),
            page_data: Vec::new(),
            ..self
        };
        for (gva, (entry_level, new_entry)) in entry_map.iter() {
            let mut page_table_gpa = new_cr3;
            let mut level = 3;

            loop {
                let table_index = reloc_builder
                    .calculate_page_table_index(page_table_gpa)
                    .expect("should be part of relocation region");
                let entry = page_tables[table_index].entry(*gva, level);

                if level == *entry_level {
                    // Allow the entry only if it matches exactly the entry it
                    // would replace. Warn regardless, as it's odd behavior from
                    // the loaded IGVM file.
                    if entry.is_present() {
                        assert_eq!(*entry, *new_entry);
                        tracing::warn!(
                            gva,
                            "page table entry relocated to an already existing identical entry"
                        );
                    } else {
                        *entry = *new_entry;
                    }

                    break;
                } else {
                    if entry.is_present() {
                        page_table_gpa = entry.gpa().expect("entry is present");
                    } else {
                        // Allocate a new page table and link it to this entry.
                        assert!(level > 0);

                        if free_table_index == page_table_len {
                            return Err(Error::NotEnoughFreeSpace);
                        }

                        let new_table_index = free_table_index;
                        free_table_index += 1;
                        let new_table_gpa =
                            Self::calculate_page_table_addr(reloc_builder.gpa, new_table_index);
                        entry.set_entry(PageTableEntryType::Pde(new_table_gpa));

                        page_table_gpa = new_table_gpa;
                    }

                    level -= 1;
                }
            }
        }

        // Truncate unused tables.
        page_tables.truncate(free_table_index);

        Ok(flatten_page_table(page_tables))
    }
}

#[cfg(test)]
mod tests {
    use super::flatten_page_table;
    use super::CpuPagingState;
    use super::PageTable;
    use super::PageTableEntryType;
    use super::PageTableRelocationBuilder;
    use super::X64_1GB_PAGE_SIZE;
    use super::X64_LARGE_PAGE_SIZE;
    use super::X64_PAGE_SIZE;
    use crate::hv_defs::Vtl;
    use range_map_vec::RangeMap;
    use zerocopy::FromBytes;
    use zerocopy::FromZeroes;

    #[derive(Debug, Clone)]
    struct PteInfo {
        va: u64,
        value: PageTableEntryType,
    }

    fn build_page_table(cr3: u64, size: usize, entries: Vec<PteInfo>) -> Vec<u8> {
        let mut page_tables = vec![PageTable::new_zeroed(); size];
        let mut free_index = 1;
        let calculate_page_table_index =
            |page_table_gpa| -> usize { ((page_table_gpa - cr3) / X64_PAGE_SIZE) as usize };

        for PteInfo { va, value } in entries {
            let mut page_table_gpa = cr3;
            let mut level = 3;
            let entry_level = match &value {
                PageTableEntryType::Leaf1GbPage(_) => 2,
                PageTableEntryType::Leaf2MbPage(_) => 1,
                PageTableEntryType::Leaf4kPage(_) => 0,
                PageTableEntryType::Pde(_) => 0, // Treat as a 4K PTE, but do not actually map.
            };

            loop {
                let table_index = calculate_page_table_index(page_table_gpa);
                let entry = page_tables[table_index].entry(va, level);

                if level == entry_level {
                    if !matches!(value, PageTableEntryType::Pde(_)) {
                        assert!(!entry.is_present());
                        entry.set_entry(value);
                    }

                    break;
                } else {
                    if entry.is_present() {
                        page_table_gpa = entry.gpa().expect("entry is present");
                    } else {
                        // Allocate a new page table and link it to this entry.
                        assert!(level > 0);
                        let new_table_index = free_index;
                        assert!(new_table_index < size);
                        free_index += 1;
                        let new_table_gpa = PageTableRelocationBuilder::calculate_page_table_addr(
                            cr3,
                            new_table_index,
                        );
                        entry.set_entry(PageTableEntryType::Pde(new_table_gpa));

                        page_table_gpa = new_table_gpa;
                    }

                    level -= 1;
                }
            }
        }

        // shrink built tables based on how many tables actually used
        page_tables.truncate(free_index);

        flatten_page_table(page_tables)
    }

    #[test]
    fn builder_test_relocation() {
        // Create a page table with the following:
        // 4K page mappings 0 - 8K.
        // 2MB page mapping 2MB - 6MB.
        // 1GB page mapping 1GB - 3GB.
        //
        // Check that relocation creates mappings of:
        // 4K reloc from 0 - 4k to 1M - 1M+4K.
        // 2MB reloc from 2MB - 4MB to 10MB to 12MB.
        // 1GB reloc from 1GB to 2GB to 6GB to 7GB.
        let original_entries = vec![
            PteInfo {
                va: 0,
                value: PageTableEntryType::Leaf4kPage(0),
            },
            PteInfo {
                va: X64_PAGE_SIZE,
                value: PageTableEntryType::Leaf4kPage(X64_PAGE_SIZE),
            },
            PteInfo {
                va: X64_LARGE_PAGE_SIZE,
                value: PageTableEntryType::Leaf2MbPage(X64_LARGE_PAGE_SIZE),
            },
            PteInfo {
                va: 2 * X64_LARGE_PAGE_SIZE,
                value: PageTableEntryType::Leaf2MbPage(2 * X64_LARGE_PAGE_SIZE),
            },
            PteInfo {
                va: X64_1GB_PAGE_SIZE,
                value: PageTableEntryType::Leaf1GbPage(X64_1GB_PAGE_SIZE),
            },
            PteInfo {
                va: 2 * X64_1GB_PAGE_SIZE,
                value: PageTableEntryType::Leaf1GbPage(2 * X64_1GB_PAGE_SIZE),
            },
        ];
        let small_reloc = 0x100000; // 1MB
        let med_reloc = 0x100000 * 8; // 8MB
        let large_reloc = X64_1GB_PAGE_SIZE * 5; // 5GB
        let reloc_entries = vec![
            PteInfo {
                va: X64_PAGE_SIZE,
                value: PageTableEntryType::Leaf4kPage(X64_PAGE_SIZE),
            },
            PteInfo {
                va: small_reloc,
                value: PageTableEntryType::Leaf4kPage(small_reloc),
            },
            PteInfo {
                va: X64_LARGE_PAGE_SIZE + med_reloc,
                value: PageTableEntryType::Leaf2MbPage(X64_LARGE_PAGE_SIZE + med_reloc),
            },
            PteInfo {
                va: 2 * X64_LARGE_PAGE_SIZE,
                value: PageTableEntryType::Leaf2MbPage(2 * X64_LARGE_PAGE_SIZE),
            },
            PteInfo {
                va: X64_1GB_PAGE_SIZE + large_reloc,
                value: PageTableEntryType::Leaf1GbPage(X64_1GB_PAGE_SIZE + large_reloc),
            },
            PteInfo {
                va: 2 * X64_1GB_PAGE_SIZE,
                value: PageTableEntryType::Leaf1GbPage(2 * X64_1GB_PAGE_SIZE),
            },
        ];
        let cr3 = 1024 * X64_1GB_PAGE_SIZE;
        let original_tables = build_page_table(cr3, 4, original_entries);
        let cr3_offset = 1024 * X64_1GB_PAGE_SIZE;
        let new_tables = build_page_table(cr3 + cr3_offset, 4, reloc_entries);

        let mut builder = PageTableRelocationBuilder::new(
            cr3,
            (original_tables.len() * 4) as u64, // test truncate behavior
            original_tables.len() as u64,
            0,
            Vtl::Vtl0,
        );

        original_tables
            .as_slice()
            .chunks_exact(X64_PAGE_SIZE as usize)
            .enumerate()
            .for_each(|(index, chunk)| {
                builder
                    .set_page_data(cr3 + index as u64 * X64_PAGE_SIZE, chunk)
                    .unwrap()
            });

        let mut reloc_map = RangeMap::new();
        reloc_map.insert(0..=X64_PAGE_SIZE - 1, small_reloc as i64);
        reloc_map.insert(
            X64_LARGE_PAGE_SIZE..=X64_LARGE_PAGE_SIZE * 2 - 1,
            med_reloc as i64,
        );
        reloc_map.insert(
            X64_1GB_PAGE_SIZE..=X64_1GB_PAGE_SIZE * 2 - 1,
            large_reloc as i64,
        );

        let built_tables = builder
            .build(cr3_offset as i64, reloc_map, CpuPagingState { cr3, cr4: 0 })
            .unwrap();

        let expected: Vec<PageTable> = new_tables
            .as_slice()
            .chunks_exact(X64_PAGE_SIZE as usize)
            .map(|chunk| PageTable::read_from_prefix(chunk).expect("chunk size is correct"))
            .collect();
        let actual: Vec<PageTable> = built_tables
            .as_slice()
            .chunks_exact(X64_PAGE_SIZE as usize)
            .map(|chunk| PageTable::read_from_prefix(chunk).expect("chunk size is correct"))
            .collect();

        assert_eq!(expected.len(), actual.len());

        compare_page_tables(&expected, &actual);
    }

    fn compare_page_tables(left: &[PageTable], right: &[PageTable]) {
        for (table_index, (left, right)) in left.iter().zip(right.iter()).enumerate() {
            for (pte_index, (left, right)) in
                left.entries.iter().zip(right.entries.iter()).enumerate()
            {
                assert_eq!(left, right, "table {} pte {}", table_index, pte_index);
            }
        }
    }

    #[test]
    fn builder_illegal_reloc() {
        // Create a page table with the following:
        // 4K page mappings 0 - 8K.
        // 2MB page mapping 2MB - 6MB.
        //
        // Supply illegal relocation of 1MB, which fails for 2MB pages.
        let original_entries = vec![
            PteInfo {
                va: 0,
                value: PageTableEntryType::Leaf4kPage(0),
            },
            PteInfo {
                va: X64_PAGE_SIZE,
                value: PageTableEntryType::Leaf4kPage(X64_PAGE_SIZE),
            },
            PteInfo {
                va: X64_LARGE_PAGE_SIZE,
                value: PageTableEntryType::Leaf2MbPage(X64_LARGE_PAGE_SIZE),
            },
            PteInfo {
                va: 2 * X64_LARGE_PAGE_SIZE,
                value: PageTableEntryType::Leaf2MbPage(2 * X64_LARGE_PAGE_SIZE),
            },
        ];
        let small_reloc = 0x100000; // 1MB
        let med_reloc = 3 * 0x100000; // 3MB
        let cr3 = 1024 * X64_1GB_PAGE_SIZE;
        let original_tables = build_page_table(cr3, 4, original_entries);
        let cr3_offset = 1024 * X64_1GB_PAGE_SIZE;

        let mut builder = PageTableRelocationBuilder::new(
            cr3,
            (original_tables.len() * 4) as u64, // test truncate behavior
            original_tables.len() as u64,
            0,
            Vtl::Vtl0,
        );

        original_tables
            .as_slice()
            .chunks_exact(X64_PAGE_SIZE as usize)
            .enumerate()
            .for_each(|(index, chunk)| {
                builder
                    .set_page_data(cr3 + index as u64 * X64_PAGE_SIZE, chunk)
                    .unwrap()
            });

        let mut reloc_map = RangeMap::new();
        reloc_map.insert(0..=X64_PAGE_SIZE - 1, small_reloc as i64);
        reloc_map.insert(
            X64_LARGE_PAGE_SIZE..=X64_LARGE_PAGE_SIZE * 2 - 1,
            med_reloc as i64,
        );

        let built_tables =
            builder.build(cr3_offset as i64, reloc_map, CpuPagingState { cr3, cr4: 0 });

        assert!(built_tables.is_err());
    }

    #[test]
    fn builder_test_allocation() {
        // test that allocating from free space works correctly
        let original_entries = vec![
            PteInfo {
                va: 0,
                value: PageTableEntryType::Leaf4kPage(0),
            },
            PteInfo {
                va: X64_LARGE_PAGE_SIZE,
                value: PageTableEntryType::Leaf2MbPage(X64_LARGE_PAGE_SIZE),
            },
            PteInfo {
                va: X64_1GB_PAGE_SIZE,
                value: PageTableEntryType::Leaf1GbPage(X64_1GB_PAGE_SIZE),
            },
        ];
        let reloc = X64_1GB_PAGE_SIZE * 512;
        let reloc_entries = vec![
            PteInfo {
                va: 0,
                value: PageTableEntryType::Pde(0),
            },
            PteInfo {
                va: reloc,
                value: PageTableEntryType::Leaf4kPage(reloc),
            },
            PteInfo {
                va: X64_LARGE_PAGE_SIZE + reloc,
                value: PageTableEntryType::Leaf2MbPage(X64_LARGE_PAGE_SIZE + reloc),
            },
            PteInfo {
                va: X64_1GB_PAGE_SIZE + reloc,
                value: PageTableEntryType::Leaf1GbPage(X64_1GB_PAGE_SIZE + reloc),
            },
        ];

        let cr3 = 2048 * X64_1GB_PAGE_SIZE;
        let original_tables = build_page_table(cr3, 4, original_entries);
        let new_tables = build_page_table(cr3, 8, reloc_entries);

        let mut builder = PageTableRelocationBuilder::new(
            cr3,
            original_tables.len() as u64 * 2,
            original_tables.len() as u64,
            0,
            Vtl::Vtl0,
        );

        original_tables
            .as_slice()
            .chunks_exact(X64_PAGE_SIZE as usize)
            .enumerate()
            .for_each(|(index, chunk)| {
                builder
                    .set_page_data(cr3 + index as u64 * X64_PAGE_SIZE, chunk)
                    .unwrap()
            });

        let mut reloc_map = RangeMap::new();
        reloc_map.insert(0..=2 * X64_1GB_PAGE_SIZE - 1, reloc as i64);
        let built_tables = builder
            .build(0, reloc_map, CpuPagingState { cr3, cr4: 0 })
            .unwrap();

        let expected: Vec<PageTable> = new_tables
            .as_slice()
            .chunks_exact(X64_PAGE_SIZE as usize)
            .map(|chunk| PageTable::read_from_prefix(chunk).expect("chunk size is correct"))
            .collect();
        let actual: Vec<PageTable> = built_tables
            .as_slice()
            .chunks_exact(X64_PAGE_SIZE as usize)
            .map(|chunk| PageTable::read_from_prefix(chunk).expect("chunk size is correct"))
            .collect();

        compare_page_tables(&expected, &actual);
    }
}
