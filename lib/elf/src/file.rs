// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

use super::types::*;
use super::{
    Elf64AddrRange, Elf64AppliedRelaIterator, Elf64Dynamic, Elf64FileRange, Elf64Hdr,
    Elf64ImageLoadSegmentIterator, Elf64ImageLoadVaddrAllocInfo, Elf64LoadSegments, Elf64Phdr,
    Elf64Relas, Elf64RelocProcessor, Elf64Shdr, Elf64ShdrFlags, Elf64ShdrIterator, Elf64Strtab,
    Elf64Symtab, ElfError,
};

/// This struct represents a parsed 64-bit ELF file. It contains information
/// about the ELF file's header, load segments, dynamic section, and more.
#[derive(Default, Debug, PartialEq)]
pub struct Elf64File<'a> {
    /// Buffer containing the ELF file data
    pub elf_file_buf: &'a [u8],
    /// The ELF file header
    pub elf_hdr: Elf64Hdr,
    /// The load segments present in the ELF file
    pub load_segments: Elf64LoadSegments,
    /// The maximum alignment requirement among load segments
    pub max_load_segment_align: Elf64Xword,
    /// THe section header string table may not be present
    pub sh_strtab: Option<Elf64Strtab<'a>>,
    pub dynamic: Option<Elf64Dynamic>,
}

impl<'a> Elf64File<'a> {
    /// This method takes a byte buffer containing the ELF file data and parses
    /// it into an [`Elf64File`] struct, providing access to the ELF file's information.
    ///
    /// # Errors
    ///
    /// Returns an [`ElfError`] if there are issues parsing the ELF file.
    pub fn read(elf_file_buf: &'a [u8]) -> Result<Self, ElfError> {
        let mut elf_hdr = Elf64Hdr::read(elf_file_buf)?;

        // Verify that the program header table is within the file bounds.
        let phdrs_off = usize::try_from(elf_hdr.e_phoff).map_err(|_| ElfError::FileTooShort)?;
        let phdr_size = usize::from(elf_hdr.e_phentsize);
        if phdr_size < 56 {
            return Err(ElfError::InvalidPhdrSize);
        }
        let phdrs_num = usize::from(elf_hdr.e_phnum);
        let phdrs_size = phdrs_num
            .checked_mul(phdr_size)
            .ok_or(ElfError::FileTooShort)?;
        let phdrs_end = phdrs_off
            .checked_add(phdrs_size)
            .ok_or(ElfError::FileTooShort)?;
        if phdrs_end > elf_file_buf.len() {
            return Err(ElfError::FileTooShort);
        }

        // Verify that the section header table is within the file bounds.
        let shdr_size = usize::from(elf_hdr.e_shentsize);
        if shdr_size < 64 {
            return Err(ElfError::InvalidShdrSize);
        }
        if elf_hdr.e_shnum == 0 && elf_hdr.e_shoff != 0 {
            // The number of section headers is stored in the first section header's
            // ->sh_size member.
            elf_hdr.e_shnum = 1;
            Self::check_section_header_table_bounds(&elf_hdr, elf_file_buf.len())?;
            let shdr0 = Self::read_shdr_from_file(elf_file_buf, &elf_hdr, 0);
            elf_hdr.e_shnum = match Elf64Word::try_from(shdr0.sh_size) {
                Ok(shnum) => shnum,
                Err(_) => return Err(ElfError::InvalidSectionIndex),
            };
        }
        Self::check_section_header_table_bounds(&elf_hdr, elf_file_buf.len())?;

        // Verify all headers once at load time, so that no error checking will
        // be needed at each and every subsequent access.
        let mut load_segments = Elf64LoadSegments::new();
        let mut max_load_segment_align = 0;
        let mut dynamic_file_range: Option<Elf64FileRange> = None;
        for i in 0..elf_hdr.e_phnum {
            let phdr = Self::read_phdr_from_file(elf_file_buf, &elf_hdr, i);
            Self::verify_phdr(&phdr, elf_file_buf.len())?;
            if phdr.p_type == Elf64Phdr::PT_LOAD {
                let vaddr_range = phdr.vaddr_range();
                if vaddr_range.vaddr_begin == vaddr_range.vaddr_end {
                    continue;
                }
                if load_segments.try_insert(vaddr_range, i).is_err() {
                    return Err(ElfError::LoadSegmentConflict);
                }
                max_load_segment_align = max_load_segment_align.max(phdr.p_align);
            } else if phdr.p_type == Elf64Phdr::PT_DYNAMIC {
                if dynamic_file_range.is_some() {
                    return Err(ElfError::DynamicPhdrConflict);
                }
                dynamic_file_range = Some(phdr.file_range());
            }
        }

        // If ->e_shstrndx == SHN_XINDEX, the actual strndx is stored in first
        // section header table's ->sh_link member.
        if elf_hdr.e_shstrndx == Elf64Shdr::SHN_XINDEX {
            if elf_hdr.e_shnum == 0 {
                return Err(ElfError::InvalidSectionIndex);
            }
            let shdr0 = Self::read_shdr_from_file(elf_file_buf, &elf_hdr, 0);
            elf_hdr.e_shstrndx = shdr0.sh_link;
        }
        if elf_hdr.e_shstrndx != Elf64Shdr::SHN_UNDEF && elf_hdr.e_shstrndx > elf_hdr.e_shnum {
            return Err(ElfError::InvalidSectionIndex);
        }

        let mut sh_strtab = None;
        for i in 0..elf_hdr.e_shnum {
            let shdr = Self::read_shdr_from_file(elf_file_buf, &elf_hdr, i);
            Self::verify_shdr(&shdr, elf_file_buf.len(), elf_hdr.e_shnum)?;

            if elf_hdr.e_shstrndx != Elf64Shdr::SHN_UNDEF && i == elf_hdr.e_shstrndx {
                if shdr.sh_type != Elf64Shdr::SHT_STRTAB {
                    return Err(ElfError::IncompatibleSectionType);
                }

                let sh_strtab_buf_range = shdr.file_range();
                let sh_strtab_buf =
                    &elf_file_buf[sh_strtab_buf_range.offset_begin..sh_strtab_buf_range.offset_end];
                sh_strtab = Some(Elf64Strtab::new(sh_strtab_buf));
            }
        }

        let dynamic = if let Some(dynamic_file_range) = dynamic_file_range {
            let dynamic_buf =
                &elf_file_buf[dynamic_file_range.offset_begin..dynamic_file_range.offset_end];
            let dynamic = Elf64Dynamic::read(dynamic_buf)?;
            Self::verify_dynamic(&dynamic)?;
            Some(dynamic)
        } else {
            None
        };

        Ok(Self {
            elf_file_buf,
            elf_hdr,
            load_segments,
            max_load_segment_align,
            sh_strtab,
            dynamic,
        })
    }

    /// Reads an ELF Program Header (Phdr) from the ELF file buffer.
    ///
    /// This function reads an ELF Program Header (Phdr) from the provided ELF file buffer
    /// based on the given index `i` and the ELF file header `elf_hdr`.
    ///
    /// # Arguments
    ///
    /// * `elf_file_buf` - The byte buffer containing the ELF file data.
    /// * `elf_hdr` - The ELF file header.
    /// * `i` - The index of the Phdr to read.
    ///
    /// # Returns
    ///
    /// The ELF Program Header (Phdr) at the specified index.
    fn read_phdr_from_file(elf_file_buf: &'a [u8], elf_hdr: &Elf64Hdr, i: Elf64Half) -> Elf64Phdr {
        let phdrs_off = usize::try_from(elf_hdr.e_phoff).unwrap();
        let phdr_size = usize::from(elf_hdr.e_phentsize);
        let i = usize::from(i);
        let phdr_off = phdrs_off + i * phdr_size;
        let phdr_buf = &elf_file_buf[phdr_off..(phdr_off + phdr_size)];
        Elf64Phdr::read(phdr_buf)
    }

    /// Verifies the integrity of an ELF Program Header (Phdr).
    ///
    /// This function verifies the integrity of an ELF Program Header (Phdr). It checks
    /// if the Phdr's type is not PT_NULL and performs additional validation to ensure
    /// the header is valid.
    ///
    /// # Arguments
    ///
    /// * `phdr` - The ELF Program Header (Phdr) to verify.
    /// * `elf_file_buf_len` - The length of the ELF file buffer.
    ///
    /// # Errors
    ///
    /// Returns an [`Err<ElfError>`] if the Phdr is invalid.
    fn verify_phdr(phdr: &Elf64Phdr, elf_file_buf_len: usize) -> Result<(), ElfError> {
        if phdr.p_type == Elf64Phdr::PT_NULL {
            return Ok(());
        }

        phdr.verify()?;

        if phdr.p_filesz != 0 {
            let file_range = phdr.file_range();
            if file_range.offset_end > elf_file_buf_len {
                return Err(ElfError::FileTooShort);
            }
        }

        Ok(())
    }

    /// Reads an ELF Program Header (Phdr) from the ELF file.
    ///
    /// This method reads an ELF Program Header (Phdr) from the ELF file based on the
    /// given index `i`.
    ///
    /// # Arguments
    ///
    /// * `i` - The index of the Phdr to read.
    ///
    /// # Returns
    ///
    /// The ELF Program Header (Phdr) at the specified index.
    pub fn read_phdr(&self, i: Elf64Half) -> Elf64Phdr {
        Self::read_phdr_from_file(self.elf_file_buf, &self.elf_hdr, i)
    }

    /// Checks if the section header table is within the ELF file bounds.
    ///
    /// This function verifies that the section header table is within the bounds of
    /// the ELF file. It checks the offsets and sizes in the ELF file header.
    ///
    /// # Arguments
    ///
    /// * `elf_hdr` - The ELF file header.
    /// * `elf_file_buf_len` - The length of the ELF file buffer.
    ///
    /// # Errors
    ///
    /// Returns an [`Err<ElfError>`] if the section header table is out of bounds.
    fn check_section_header_table_bounds(
        elf_hdr: &Elf64Hdr,
        elf_file_buf_len: usize,
    ) -> Result<(), ElfError> {
        // Verify that the section header table is within the file bounds.
        let shdrs_off = usize::try_from(elf_hdr.e_shoff).map_err(|_| ElfError::FileTooShort)?;
        let shdr_size = usize::from(elf_hdr.e_shentsize);
        let shdrs_num = usize::try_from(elf_hdr.e_shnum).unwrap();
        let shdrs_size = shdrs_num
            .checked_mul(shdr_size)
            .ok_or(ElfError::FileTooShort)?;
        let shdrs_end = shdrs_off
            .checked_add(shdrs_size)
            .ok_or(ElfError::FileTooShort)?;
        if shdrs_end > elf_file_buf_len {
            return Err(ElfError::FileTooShort);
        }
        Ok(())
    }

    /// Reads an ELF Section Header (Shdr) from the ELF file buffer.
    ///
    /// This function reads an ELF Section Header (Shdr) from the provided ELF file buffer
    /// based on the given index `i` and the ELF file header `elf_hdr`.
    ///
    /// # Arguments
    ///
    /// * `elf_file_buf` - The byte buffer containing the ELF file data.
    /// * `elf_hdr` - The ELF file header.
    /// * `i` - The index of the Shdr to read.
    ///
    /// # Returns
    ///
    /// The ELF Section Header (Shdr) at the specified index.
    fn read_shdr_from_file(elf_file_buf: &'a [u8], elf_hdr: &Elf64Hdr, i: Elf64Word) -> Elf64Shdr {
        let shdrs_off = usize::try_from(elf_hdr.e_shoff).unwrap();
        let shdr_size = usize::from(elf_hdr.e_shentsize);
        let i = usize::try_from(i).unwrap();
        let shdr_off = shdrs_off + i * shdr_size;
        let shdr_buf = &elf_file_buf[shdr_off..(shdr_off + shdr_size)];
        Elf64Shdr::read(shdr_buf)
    }

    /// Verifies the integrity of an ELF Section Header (Shdr).
    ///
    /// This function verifies the integrity of an ELF Section Header (Shdr). It checks
    /// if the Shdr's type is not SHT_NULL and performs additional validation to ensure
    /// the header is valid.
    ///
    /// # Arguments
    ///
    /// * `shdr` - The ELF Section Header (Shdr) to verify.
    /// * `elf_file_buf_len` - The length of the ELF file buffer.
    /// * `shnum` - The number of section headers.
    ///
    /// # Errors
    ///
    /// Returns an [`Err<ElfError>`] if the Shdr is invalid.
    fn verify_shdr(
        shdr: &Elf64Shdr,
        elf_file_buf_len: usize,
        shnum: Elf64Word,
    ) -> Result<(), ElfError> {
        if shdr.sh_type == Elf64Shdr::SHT_NULL {
            return Ok(());
        }

        shdr.verify()?;

        if shdr.sh_link > shnum
            || shdr.sh_flags.contains(Elf64ShdrFlags::INFO_LINK) && shdr.sh_info > shnum
        {
            return Err(ElfError::InvalidSectionIndex);
        }

        if shdr.sh_type != Elf64Shdr::SHT_NOBITS {
            let file_range = shdr.file_range();
            if file_range.offset_end > elf_file_buf_len {
                return Err(ElfError::FileTooShort);
            }
        }

        Ok(())
    }

    /// Reads an ELF Section Header (Shdr) from the ELF file.
    ///
    /// This method reads an ELF Section Header (Shdr) from the ELF file based on the
    /// given index `i`.
    ///
    /// # Arguments
    ///
    /// * `i` - The index of the Shdr to read.
    ///
    /// # Returns
    ///
    /// The ELF Section Header (Shdr) at the specified index.
    pub fn read_shdr(&self, i: Elf64Word) -> Elf64Shdr {
        Self::read_shdr_from_file(self.elf_file_buf, &self.elf_hdr, i)
    }

    /// Creates an iterator over ELF Section Headers (Shdrs) in the ELF file.
    ///
    /// This method creates an iterator over ELF Section Headers (Shdrs) in the ELF file.
    /// It allows iterating through the section headers for processing.
    ///
    /// # Returns
    ///
    /// An [`Elf64ShdrIterator`] over the ELF Section Headers.
    pub fn shdrs_iter(&self) -> Elf64ShdrIterator<'_> {
        Elf64ShdrIterator::new(self)
    }

    /// Verifies the integrity of the ELF Dynamic section.
    ///
    /// This function verifies the integrity of the ELF Dynamic section.
    ///
    /// # Arguments
    ///
    /// * `dynamic` - The ELF Dynamic section to verify.
    ///
    /// # Errors
    ///
    /// Returns an [`Err<ElfError>`] if the Dynamic section is invalid.
    fn verify_dynamic(dynamic: &Elf64Dynamic) -> Result<(), ElfError> {
        dynamic.verify()?;
        Ok(())
    }

    /// Maps a virtual address (Vaddr) range to a corresponding file offset.
    ///
    /// This function maps a given virtual address (Vaddr) range to the corresponding
    /// file offset within the ELF file. It takes the beginning `vaddr_begin` and an
    /// optional `vaddr_end` (if provided), and returns the corresponding file offset
    /// range as an [`Elf64FileRange`].
    ///
    /// # Arguments
    ///
    /// * `vaddr_begin` - The starting virtual address of the range.
    /// * `vaddr_end` - An optional ending virtual address of the range. If not provided,
    ///   the function assumes a range of size 1.
    ///
    /// # Returns
    ///
    /// A [`Result`] containing an [`Elf64FileRange`] representing the file offset range.
    ///
    /// # Errors
    ///
    /// Returns an [`Err<ElfError>`] in the following cases:
    ///
    /// * If `vaddr_begin` is [`Elf64Addr::MAX`], indicating an unmapped virtual address range.
    /// * If the virtual address range is not found within any loaded segment.
    /// * If the file offset calculations result in an invalid file range.
    /// * If the virtual address range extends beyond the loaded segment's file content,
    ///   indicating an unbacked virtual address range.
    fn map_vaddr_to_file_off(
        &self,
        vaddr_begin: Elf64Addr,
        vaddr_end: Option<Elf64Addr>,
    ) -> Result<Elf64FileRange, ElfError> {
        if vaddr_begin == Elf64Addr::MAX {
            return Err(ElfError::UnmappedVaddrRange);
        }
        let vaddr_range = Elf64AddrRange {
            vaddr_begin,
            vaddr_end: vaddr_end.unwrap_or(vaddr_begin + 1),
        };
        let (phdr_index, offset) = match self.load_segments.lookup_vaddr_range(&vaddr_range) {
            Some(load_segment) => (load_segment.0, load_segment.1),
            None => return Err(ElfError::UnmappedVaddrRange),
        };

        let phdr = self.read_phdr(phdr_index);
        let segment_file_range = phdr.file_range();
        let offset_in_segment = usize::try_from(offset).map_err(|_| ElfError::InvalidFileRange)?;
        let offset_begin = segment_file_range
            .offset_begin
            .checked_add(offset_in_segment)
            .ok_or(ElfError::InvalidFileRange)?;
        let offset_end = match vaddr_end {
            Some(vaddr_end) => {
                let len = vaddr_end - vaddr_begin;
                let len = usize::try_from(len).map_err(|_| ElfError::InvalidFileRange)?;
                let offset_end = offset_begin
                    .checked_add(len)
                    .ok_or(ElfError::InvalidFileRange)?;

                // A PT_LOAD segment is not necessarily backed completely by ELF
                // file content: ->p_filesz can be <= ->memsz.
                if offset_end > segment_file_range.offset_end {
                    return Err(ElfError::UnbackedVaddrRange);
                }

                offset_end
            }
            None => {
                // The query did not specify an end address, as can e.g. happen
                // when examining some table referenced from .dynamic with
                // unknown size.  Return the upper segment bound.
                segment_file_range.offset_end
            }
        };
        Ok(Elf64FileRange {
            offset_begin,
            offset_end,
        })
    }

    /// Maps a virtual address range to a slice of bytes from the ELF file buffer.
    ///
    /// This function takes a virtual address range specified by `vaddr_begin` and
    /// optionally `vaddr_end` and maps it to a slice of bytes from the ELF file buffer.
    ///
    /// If `vaddr_end` is [`Some`], the function maps the range from `vaddr_begin` (inclusive)
    /// to `vaddr_end` (exclusive) to a slice of bytes from the ELF file buffer.
    ///
    /// If `vaddr_end` is [`None`], the function maps the range from `vaddr_begin` to the end
    /// of the virtual address range associated with `vaddr_begin` to a slice of bytes from
    /// the ELF file buffer.
    ///
    /// # Arguments
    ///
    /// * `vaddr_begin` - The starting virtual address of the range to map.
    /// * `vaddr_end` - An optional ending virtual address of the range to map.
    ///
    /// # Returns
    ///
    /// - [`Ok<slice>`]: If the virtual address range is valid and successfully mapped, returns
    ///   a reference to the corresponding slice of bytes from the ELF file buffer.
    /// - [`Err<ElfError>`]: If an error occurs during mapping, such as an unmapped or unbacked
    ///   virtual address range, returns an [`ElfError`].
    fn map_vaddr_to_file_buf(
        &self,
        vaddr_begin: Elf64Addr,
        vaddr_end: Option<Elf64Addr>,
    ) -> Result<&[u8], ElfError> {
        let file_range = self.map_vaddr_to_file_off(vaddr_begin, vaddr_end)?;
        Ok(&self.elf_file_buf[file_range.offset_begin..file_range.offset_end])
    }

    // For PIE executables, relieve the using code from offset calculations due
    // to address alignment. Do it here and consistently. The address passed here
    // may be either
    // - a load address corresponding as-is to the first load segment's beginning or
    // - the load address corresponding as-is to the first load segment's
    //   beginning rounded down to match the alginment constraints.
    // The passed address will be mapped to the first variant in either case.
    fn image_load_addr(&self, image_load_addr: Elf64Addr) -> Elf64Addr {
        if self.max_load_segment_align == 0 {
            image_load_addr
        } else {
            let aligned_image_load_addr = image_load_addr & !(self.max_load_segment_align - 1);
            aligned_image_load_addr + self.image_load_align_offset()
        }
    }

    /// Calculates the alignment offset for the image load address.
    ///
    /// This function calculates the alignment offset that needs to be applied to the
    /// image's load address to ensure alignment with the maximum alignment constraint
    /// of all load segments.
    ///
    /// If the `max_load_segment_align` is 0 (indicating no alignment constraints), the
    /// offset is 0.
    ///
    /// If there are load segments with alignment constraints, this function determines
    /// the offset needed to align the image load address with the maximum alignment
    /// constraint among all load segments.
    ///
    /// # Returns
    ///
    /// - [`Elf64Off`]: The alignment offset for the image's load address.
    fn image_load_align_offset(&self) -> Elf64Off {
        if self.max_load_segment_align == 0 {
            return 0;
        }

        // The first segment loaded is not necessarily aligned to the maximum of
        // all segment alignment constraints. Determine the offset from the next
        // lower aligned address to the first segment's beginning.
        self.load_segments.total_vaddr_range().vaddr_begin & (self.max_load_segment_align - 1)
    }

    // The ELF "base address" has a well-defined meaning: it is defined in the
    // spec as the difference between the lowest address of the actual memory
    // image the file has been loaded into and the lowest vaddr of all the
    // PT_LOAD program headers. Calculate it in two's complement representation.
    fn load_base(&self, image_load_addr: Elf64Addr) -> Elf64Xword {
        let image_load_addr = self.image_load_addr(image_load_addr);
        image_load_addr.wrapping_sub(self.load_segments.total_vaddr_range().vaddr_begin)
    }

    pub fn image_load_vaddr_alloc_info(&self) -> Elf64ImageLoadVaddrAllocInfo {
        let mut range = self.load_segments.total_vaddr_range();

        if self.max_load_segment_align != 0 {
            range.vaddr_begin &= !(self.max_load_segment_align - 1);
        }

        let pie = self.dynamic.as_ref().map(|d| d.is_pie()).unwrap_or(false);
        let align = if pie {
            Some(self.max_load_segment_align)
        } else {
            None
        };

        Elf64ImageLoadVaddrAllocInfo { range, align }
    }

    /// Creates an iterator over the ELF segments that are part of the loaded image.
    ///
    /// This function returns an iterator that allows iterating over the ELF segments
    /// belonging to the loaded image. It takes the `image_load_addr`, which represents
    /// the virtual address where the ELF image is loaded in memory. The iterator yields
    /// [`super::Elf64ImageLoadSegment`] instances.
    ///
    /// # Arguments
    ///
    /// * `image_load_addr` - The virtual address where the ELF image is loaded in memory.
    ///
    /// # Returns
    ///
    /// An [`Elf64ImageLoadSegmentIterator`] over the loaded image segments.
    pub fn image_load_segment_iter(
        &'a self,
        image_load_addr: Elf64Addr,
    ) -> Elf64ImageLoadSegmentIterator<'a> {
        let load_base = self.load_base(image_load_addr);
        Elf64ImageLoadSegmentIterator {
            elf_file: self,
            load_base,
            next: 0,
        }
    }

    ///
    /// This function processes dynamic relocations (relas) in the ELF file and applies them
    /// to the loaded image. It takes a generic `rela_proc` parameter that should implement the
    /// [`Elf64RelocProcessor`] trait, allowing custom relocation processing logic.
    ///
    /// The `image_load_addr` parameter specifies the virtual address where the ELF image is
    /// loaded in memory.
    ///
    /// # Arguments
    ///
    /// * `rela_proc` - A relocation processor implementing the [`Elf64RelocProcessor`] trait.
    /// * `image_load_addr` - The virtual address where the ELF image is loaded in memory.
    ///
    /// # Returns
    ///
    /// - [`Ok<Some<iterator>>`]: If relocations are successfully applied, returns an iterator
    ///   over the applied relocations.
    /// - [`Ok<None>`]: If no relocations are present or an error occurs during processing,
    ///   returns [`None`].
    /// - [`Err<ElfError>`]: If an error occurs while processing relocations, returns an
    ///   [`ElfError`].
    pub fn apply_dyn_relas<RP: Elf64RelocProcessor>(
        &'a self,
        rela_proc: RP,
        image_load_addr: Elf64Addr,
    ) -> Result<Option<Elf64AppliedRelaIterator<'a, RP>>, ElfError> {
        let dynamic = match &self.dynamic {
            Some(dynamic) => dynamic,
            None => return Ok(None),
        };
        let dynamic_rela = match &dynamic.rela {
            Some(dynamic_rela) => dynamic_rela,
            None => return Ok(None),
        };

        let load_base = self.load_base(image_load_addr);

        let relas_file_range = dynamic_rela.vaddr_range();
        let relas_buf = self.map_vaddr_to_file_buf(
            relas_file_range.vaddr_begin,
            Some(relas_file_range.vaddr_end),
        )?;
        let relas = Elf64Relas::new(relas_buf, dynamic_rela.entsize)?;

        let symtab = match &dynamic.symtab {
            Some(dynamic_symtab) => {
                let syms_buf = self.map_vaddr_to_file_buf(dynamic_symtab.base_vaddr, None)?;
                let symtab = Elf64Symtab::new(syms_buf, dynamic_symtab.entsize)?;
                Some(symtab)
            }
            None => None,
        };

        Ok(Some(Elf64AppliedRelaIterator::new(
            rela_proc,
            load_base,
            &self.load_segments,
            relas,
            symtab,
        )))
    }

    /// Retrieves the entry point virtual address of the ELF image.
    ///
    /// This function returns the virtual address of the entry point of the ELF image.
    /// The `image_load_addr` parameter specifies the virtual address where the ELF image
    /// is loaded in memory, and the entry point address is adjusted accordingly.
    ///
    /// # Arguments
    ///
    /// * `image_load_addr` - The virtual address where the ELF image is loaded in memory.
    ///
    /// # Returns
    ///
    /// The adjusted entry point virtual address.
    pub fn get_entry(&self, image_load_addr: Elf64Addr) -> Elf64Addr {
        self.elf_hdr
            .e_entry
            .wrapping_add(self.load_base(image_load_addr))
    }
}
