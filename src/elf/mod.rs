// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

extern crate alloc;

use alloc::vec::Vec;
use bitflags::bitflags;
use core::cmp;
use core::convert;
use core::ffi;
use core::fmt;
use core::matches;
use core::mem;

#[derive(Debug)]
pub enum ElfError {
    FileTooShort,

    InvalidAddressRange,
    InvalidAddressAlignment,
    InvalidFileRange,
    UnmappedVaddrRange,
    UnbackedVaddrRange,

    UnrecognizedMagic,
    UnsupportedClass,
    UnsupportedEndianess,
    UnsupportedOsAbi,
    UnsupportedType,
    UnsupportedMachine,
    UnsupportedVersion,
    InvalidPhdrSize,
    InvalidShdrSize,

    InvalidSegmentSize,
    UnalignedSegmentAddress,
    LoadSegmentConflict,
    DynamicPhdrConflict,

    UnterminatedDynamicSection,
    DynamicFieldConflict,
    UnrecognizedDynamicField,
    MissingDynamicField,

    InvalidSectionIndex,
    IncompatibleSectionType,

    InvalidStrtabString,

    InvalidSymbolEntrySize,
    InvalidSymbolIndex,

    InvalidRelocationEntrySize,
    UnrecognizedRelocationType,
    InvalidRelocationOffset,
    RelocationAgainstUndefSymbol,
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::FileTooShort => {
                write!(f, "ELF file too short")
            }

            Self::InvalidAddressRange => {
                write!(f, "invalid ELF address range")
            }
            Self::InvalidAddressAlignment => {
                write!(f, "invalid ELF address alignment")
            }
            Self::InvalidFileRange => {
                write!(f, "invalid ELF file range")
            }
            Self::UnmappedVaddrRange => {
                write!(f, "reference to unmapped ELF address range")
            }
            Self::UnbackedVaddrRange => {
                write!(f, "reference ELF address range not backed by file")
            }

            Self::UnrecognizedMagic => {
                write!(f, "unrecognized ELF magic")
            }
            Self::UnsupportedClass => {
                write!(f, "unsupported ELF class")
            }
            Self::UnsupportedEndianess => {
                write!(f, "unsupported ELF endianess")
            }
            Self::UnsupportedOsAbi => {
                write!(f, "unsupported ELF ABI")
            }
            Self::UnsupportedType => {
                write!(f, "unsupported ELF file type")
            }
            Self::UnsupportedMachine => {
                write!(f, "unsupported ELF machine")
            }
            Self::UnsupportedVersion => {
                write!(f, "unsupported ELF version")
            }
            Self::InvalidPhdrSize => {
                write!(f, "invalid ELF program header size")
            }
            Self::InvalidShdrSize => {
                write!(f, "invalid ELF section header size")
            }

            Self::InvalidSegmentSize => {
                write!(f, "invalid ELF segment size")
            }
            Self::UnalignedSegmentAddress => {
                write!(f, "unaligned ELF segment address")
            }
            Self::LoadSegmentConflict => {
                write!(f, "ELF PT_LOAD segment conflict")
            }
            Self::DynamicPhdrConflict => {
                write!(f, "multiple ELF PT_DYNAMIC program headers")
            }

            Self::UnterminatedDynamicSection => {
                write!(f, "unterminated ELF dynamic section")
            }
            Self::DynamicFieldConflict => {
                write!(f, "conflicting fields in ELF dynamic section")
            }
            Self::UnrecognizedDynamicField => {
                write!(f, "unrecognized field in ELF dynamic section")
            }
            Self::MissingDynamicField => {
                write!(f, "missing field in ELF dynamic section")
            }

            Self::InvalidSectionIndex => {
                write!(f, "invalid ELF section index")
            }
            Self::IncompatibleSectionType => {
                write!(f, "unexpected ELF section type")
            }

            Self::InvalidStrtabString => {
                write!(f, "invalid ELF strtab string")
            }

            Self::InvalidSymbolEntrySize => {
                write!(f, "invalid ELF symbol entry size")
            }
            Self::InvalidSymbolIndex => {
                write!(f, "invalid ELF symbol index")
            }

            Self::InvalidRelocationEntrySize => {
                write!(f, "invalid ELF relocation entry size")
            }
            Self::UnrecognizedRelocationType => {
                write!(f, "unrecognized ELF relocation type")
            }
            Self::InvalidRelocationOffset => {
                write!(f, "ELF relocation offset out of bounds")
            }
            Self::RelocationAgainstUndefSymbol => {
                write!(f, "ELF relocation against undefined symbol")
            }
        }
    }
}

pub type Elf64Addr = u64;
pub type Elf64Off = u64;
pub type Elf64Half = u16;
pub type Elf64Word = u32;
#[allow(unused)]
pub type Elf64Sword = i32;
pub type Elf64Xword = u64;
pub type Elf64Sxword = i64;
pub type Elf64char = u8;

#[derive(PartialEq, Eq, Debug)]
pub struct Elf64AddrRange {
    pub vaddr_begin: Elf64Addr,
    pub vaddr_end: Elf64Addr,
}

impl Elf64AddrRange {
    pub fn len(&self) -> Elf64Xword {
        self.vaddr_end - self.vaddr_begin
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl convert::TryFrom<(Elf64Addr, Elf64Xword)> for Elf64AddrRange {
    type Error = ElfError;

    fn try_from(value: (Elf64Addr, Elf64Xword)) -> Result<Self, Self::Error> {
        let vaddr_begin = value.0;
        let size = value.1;
        let vaddr_end = vaddr_begin
            .checked_add(size)
            .ok_or(ElfError::InvalidAddressRange)?;
        Ok(Self {
            vaddr_begin,
            vaddr_end,
        })
    }
}

impl cmp::PartialOrd for Elf64AddrRange {
    fn partial_cmp(&self, other: &Elf64AddrRange) -> Option<cmp::Ordering> {
        if self.vaddr_end <= other.vaddr_begin {
            Some(cmp::Ordering::Less)
        } else if self.vaddr_begin >= other.vaddr_end {
            Some(cmp::Ordering::Greater)
        } else if self == other {
            Some(cmp::Ordering::Equal)
        } else {
            None
        }
    }
}

pub struct Elf64FileRange {
    pub offset_begin: usize,
    pub offset_end: usize,
}

impl convert::TryFrom<(Elf64Off, Elf64Xword)> for Elf64FileRange {
    type Error = ElfError;

    fn try_from(value: (Elf64Off, Elf64Xword)) -> Result<Self, Self::Error> {
        let offset_begin = usize::try_from(value.0).map_err(|_| ElfError::InvalidFileRange)?;
        let size = usize::try_from(value.1).map_err(|_| ElfError::InvalidFileRange)?;
        let offset_end = offset_begin
            .checked_add(size)
            .ok_or(ElfError::InvalidFileRange)?;
        Ok(Self {
            offset_begin,
            offset_end,
        })
    }
}

pub struct Elf64File<'a> {
    elf_file_buf: &'a [u8],
    elf_hdr: Elf64Hdr,
    load_segments: Elf64LoadSegments,
    max_load_segment_align: Elf64Xword,
    #[allow(unused)]
    sh_strtab: Option<Elf64Strtab<'a>>,
    dynamic: Option<Elf64Dynamic>,
}

impl<'a> Elf64File<'a> {
    pub fn read(elf_file_buf: &'a [u8]) -> Result<Self, ElfError> {
        let mut elf_hdr = Elf64Hdr::read(elf_file_buf)?;

        // Verify that the program header table is within the file bounds.
        let phdrs_off = usize::try_from(elf_hdr.e_phoff).map_err(|_| ElfError::FileTooShort)?;
        let phdr_size = usize::try_from(elf_hdr.e_phentsize).unwrap();
        if phdr_size < 56 {
            return Err(ElfError::InvalidPhdrSize);
        }
        let phdrs_num = usize::try_from(elf_hdr.e_phnum).unwrap();
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
        let shdr_size = usize::try_from(elf_hdr.e_shentsize).unwrap();
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

        let mut sh_strtab: Option<Elf64Strtab> = None;
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

    fn read_phdr_from_file(elf_file_buf: &'a [u8], elf_hdr: &Elf64Hdr, i: Elf64Half) -> Elf64Phdr {
        let phdrs_off = usize::try_from(elf_hdr.e_phoff).unwrap();
        let phdr_size = usize::try_from(elf_hdr.e_phentsize).unwrap();
        let i = usize::try_from(i).unwrap();
        let phdr_off = phdrs_off + i * phdr_size;
        let phdr_buf = &elf_file_buf[phdr_off..(phdr_off + phdr_size)];
        Elf64Phdr::read(phdr_buf)
    }

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

    fn read_phdr(&self, i: Elf64Half) -> Elf64Phdr {
        Self::read_phdr_from_file(self.elf_file_buf, &self.elf_hdr, i)
    }

    fn check_section_header_table_bounds(
        elf_hdr: &Elf64Hdr,
        elf_file_buf_len: usize,
    ) -> Result<(), ElfError> {
        // Verify that the section header table is within the file bounds.
        let shdrs_off = usize::try_from(elf_hdr.e_shoff).map_err(|_| ElfError::FileTooShort)?;
        let shdr_size = usize::try_from(elf_hdr.e_shentsize).unwrap();
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

    fn read_shdr_from_file(elf_file_buf: &'a [u8], elf_hdr: &Elf64Hdr, i: Elf64Word) -> Elf64Shdr {
        let shdrs_off = usize::try_from(elf_hdr.e_shoff).unwrap();
        let shdr_size = usize::try_from(elf_hdr.e_shentsize).unwrap();
        let i = usize::try_from(i).unwrap();
        let shdr_off = shdrs_off + i * shdr_size;
        let shdr_buf = &elf_file_buf[shdr_off..(shdr_off + shdr_size)];
        Elf64Shdr::read(shdr_buf)
    }

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

        let file_range = shdr.file_range();
        if file_range.offset_end > elf_file_buf_len {
            return Err(ElfError::FileTooShort);
        }

        Ok(())
    }

    fn read_shdr(&self, i: Elf64Word) -> Elf64Shdr {
        Self::read_shdr_from_file(self.elf_file_buf, &self.elf_hdr, i)
    }

    pub fn shdrs_iter(&self) -> Elf64ShdrIterator {
        Elf64ShdrIterator::new(self)
    }

    fn verify_dynamic(dynamic: &Elf64Dynamic) -> Result<(), ElfError> {
        dynamic.verify()?;
        Ok(())
    }

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

    pub fn get_entry(&self, image_load_addr: Elf64Addr) -> Elf64Addr {
        self.elf_hdr
            .e_entry
            .wrapping_add(self.load_base(image_load_addr))
    }
}

#[derive(Debug)]
pub struct Elf64Hdr {
    #[allow(unused)]
    e_ident: [Elf64char; 16],
    #[allow(unused)]
    e_type: Elf64Half,
    #[allow(unused)]
    e_machine: Elf64Half,
    #[allow(unused)]
    e_version: Elf64Word,
    e_entry: Elf64Addr,
    e_phoff: Elf64Off,
    e_shoff: Elf64Off,
    #[allow(unused)]
    e_flags: Elf64Word,
    #[allow(unused)]
    e_ehsize: Elf64Half,
    e_phentsize: Elf64Half,
    e_phnum: Elf64Half,
    e_shentsize: Elf64Half,
    e_shnum: Elf64Word, // The actual Elf64Hdr entry is Elf64Half, on overflow it's read from section
    // table entry zero
    e_shstrndx: Elf64Word, // The actual Elf64Hdr entry is Elf64Half, on overflow it's read from section
                           // table entry zero
}

impl Elf64Hdr {
    const EI_MAG0: usize = 0;
    const EI_CLASS: usize = 4;
    const EI_DATA: usize = 5;
    const EI_VERSION: usize = 6;
    const EI_OSABI: usize = 7;

    const ELFMAG: [Elf64char; 4] = [0x7f, b'E', b'L', b'F'];

    const ELFCLASS64: Elf64char = 2;

    const ELFDATA2LSB: Elf64char = 1;

    const ELFOSABI_NONE: Elf64char = 0;
    const ELFOSABI_GNU: Elf64char = 3;

    const ET_EXEC: Elf64Half = 2;

    const EM_X86_64: Elf64Half = 62;

    const EV_CURRENT: Elf64Word = 1;

    fn read(buf: &[u8]) -> Result<Self, ElfError> {
        // Examine the e_ident[] magic.
        if buf.len() < 16 {
            return Err(ElfError::FileTooShort);
        }
        let e_ident: [Elf64char; 16] = buf[..16].try_into().unwrap();
        if e_ident[Self::EI_MAG0..(Self::EI_MAG0 + mem::size_of_val(&Self::ELFMAG))] != Self::ELFMAG
        {
            return Err(ElfError::UnrecognizedMagic);
        } else if e_ident[Self::EI_CLASS] != Self::ELFCLASS64 {
            return Err(ElfError::UnsupportedClass);
        } else if e_ident[Self::EI_DATA] != Self::ELFDATA2LSB {
            return Err(ElfError::UnsupportedEndianess);
        } else if e_ident[Self::EI_VERSION] != Self::EV_CURRENT as Elf64char {
            return Err(ElfError::UnsupportedVersion);
        } else if e_ident[Self::EI_OSABI] != Self::ELFOSABI_NONE
            && e_ident[Self::EI_OSABI] != Self::ELFOSABI_GNU
        {
            return Err(ElfError::UnsupportedOsAbi);
        }

        // ELF file is confirmed to be of ELFCLASS64, so the total header size
        // should equal 64 bytes.
        if buf.len() < 64 {
            return Err(ElfError::FileTooShort);
        }
        let e_type = Elf64Half::from_le_bytes(buf[16..18].try_into().unwrap());
        let e_machine = Elf64Half::from_le_bytes(buf[18..20].try_into().unwrap());
        let e_version = Elf64Word::from_le_bytes(buf[20..24].try_into().unwrap());
        let e_entry = Elf64Addr::from_le_bytes(buf[24..32].try_into().unwrap());
        let e_phoff = Elf64Off::from_le_bytes(buf[32..40].try_into().unwrap());
        let e_shoff = Elf64Off::from_le_bytes(buf[40..48].try_into().unwrap());
        let e_flags = Elf64Word::from_le_bytes(buf[48..52].try_into().unwrap());
        let e_ehsize = Elf64Half::from_le_bytes(buf[52..54].try_into().unwrap());
        let e_phentsize = Elf64Half::from_le_bytes(buf[54..56].try_into().unwrap());
        let e_phnum = Elf64Half::from_le_bytes(buf[56..58].try_into().unwrap());
        let e_shentsize = Elf64Half::from_le_bytes(buf[58..60].try_into().unwrap());
        let e_shnum = Elf64Half::from_le_bytes(buf[60..62].try_into().unwrap()) as Elf64Word;
        let e_shstrndx = Elf64Half::from_le_bytes(buf[62..64].try_into().unwrap()) as Elf64Word;

        if e_type != Self::ET_EXEC {
            return Err(ElfError::UnsupportedType);
        }
        if e_machine != Self::EM_X86_64 {
            return Err(ElfError::UnsupportedMachine);
        }
        if e_version != Self::EV_CURRENT {
            return Err(ElfError::UnsupportedVersion);
        }

        Ok(Self {
            e_ident,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        })
    }
}

#[derive(Debug)]
pub struct Elf64Phdr {
    pub p_type: Elf64Word,
    pub p_flags: Elf64PhdrFlags,
    pub p_offset: Elf64Off,
    pub p_vaddr: Elf64Addr,
    pub p_paddr: Elf64Addr,
    pub p_filesz: Elf64Xword,
    pub p_memsz: Elf64Xword,
    pub p_align: Elf64Xword,
}

bitflags! {
    pub struct Elf64PhdrFlags : Elf64Word {
        const EXECUTE = 0x01;
        const WRITE   = 0x02;
        const READ    = 0x04;
    }
}

impl Elf64Phdr {
    pub const PT_NULL: Elf64Word = 1;
    pub const PT_LOAD: Elf64Word = 1;
    pub const PT_DYNAMIC: Elf64Word = 2;

    fn read(phdr_buf: &[u8]) -> Self {
        let p_type = Elf64Word::from_le_bytes(phdr_buf[0..4].try_into().unwrap());
        let p_flags = Elf64Word::from_le_bytes(phdr_buf[4..8].try_into().unwrap());
        let p_offset = Elf64Off::from_le_bytes(phdr_buf[8..16].try_into().unwrap());
        let p_vaddr = Elf64Addr::from_le_bytes(phdr_buf[16..24].try_into().unwrap());
        let p_paddr = Elf64Addr::from_le_bytes(phdr_buf[24..32].try_into().unwrap());
        let p_filesz = Elf64Xword::from_le_bytes(phdr_buf[32..40].try_into().unwrap());
        let p_memsz = Elf64Xword::from_le_bytes(phdr_buf[40..48].try_into().unwrap());
        let p_align = Elf64Xword::from_le_bytes(phdr_buf[48..56].try_into().unwrap());

        let p_flags = Elf64PhdrFlags::from_bits_truncate(p_flags);

        Self {
            p_type,
            p_flags,
            p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_align,
        }
    }

    fn verify(&self) -> Result<(), ElfError> {
        if self.p_type == Self::PT_NULL {
            return Ok(());
        }

        if self.p_type == Self::PT_LOAD && self.p_memsz < self.p_filesz {
            return Err(ElfError::InvalidSegmentSize);
        }

        if self.p_align != 0 {
            if !self.p_align.is_power_of_two() {
                return Err(ElfError::InvalidAddressAlignment);
            }
            if self.p_vaddr & (self.p_align - 1) != 0 {
                return Err(ElfError::UnalignedSegmentAddress);
            }
        }

        if self.p_filesz != 0 {
            Elf64FileRange::try_from((self.p_offset, self.p_filesz))?;
        }
        if self.p_memsz != 0 {
            Elf64AddrRange::try_from((self.p_vaddr, self.p_memsz))?;
        }

        Ok(())
    }

    fn file_range(&self) -> Elf64FileRange {
        Elf64FileRange::try_from((self.p_offset, self.p_filesz)).unwrap()
    }

    fn vaddr_range(&self) -> Elf64AddrRange {
        Elf64AddrRange::try_from((self.p_vaddr, self.p_memsz)).unwrap()
    }
}

#[derive(Debug)]
pub struct Elf64Shdr {
    pub sh_name: Elf64Word,
    sh_type: Elf64Word,
    sh_flags: Elf64ShdrFlags,
    sh_addr: Elf64Addr,
    sh_offset: Elf64Off,
    sh_size: Elf64Xword,
    sh_link: Elf64Word,
    sh_info: Elf64Word,
    sh_addralign: Elf64Xword,
    #[allow(unused)]
    sh_entsize: Elf64Xword,
}

bitflags! {
    pub struct Elf64ShdrFlags : Elf64Xword {
        const WRITE            = 0x001;
        const ALLOC            = 0x002;
        const EXECINSTR        = 0x004;
        const MERGE            = 0x010;
        const STRINGS          = 0x020;
        const INFO_LINK        = 0x040;
        const LINK_ORDER       = 0x080;
        const OS_NONCONFORMING = 0x100;
        const GROUP            = 0x200;
        const TLS              = 0x400;
        const COMPRESSED       = 0x800;
    }
}

impl Elf64Shdr {
    const SHN_UNDEF: Elf64Word = 0;
    const SHN_ABS: Elf64Word = 0xfff1;
    const SHN_XINDEX: Elf64Word = 0xffff;

    pub const SHT_NULL: Elf64Word = 0;
    pub const SHT_STRTAB: Elf64Word = 3;
    pub const SHT_NOBITS: Elf64Word = 8;

    fn read(shdr_buf: &'_ [u8]) -> Self {
        let sh_name = Elf64Word::from_le_bytes(shdr_buf[0..4].try_into().unwrap());
        let sh_type = Elf64Word::from_le_bytes(shdr_buf[4..8].try_into().unwrap());
        let sh_flags = Elf64Xword::from_le_bytes(shdr_buf[8..16].try_into().unwrap());
        let sh_addr = Elf64Addr::from_le_bytes(shdr_buf[16..24].try_into().unwrap());
        let sh_offset = Elf64Off::from_le_bytes(shdr_buf[24..32].try_into().unwrap());
        let sh_size = Elf64Xword::from_le_bytes(shdr_buf[32..40].try_into().unwrap());
        let sh_link = Elf64Word::from_le_bytes(shdr_buf[40..44].try_into().unwrap());
        let sh_info = Elf64Word::from_le_bytes(shdr_buf[44..48].try_into().unwrap());
        let sh_addralign = Elf64Xword::from_le_bytes(shdr_buf[48..56].try_into().unwrap());
        let sh_entsize = Elf64Xword::from_le_bytes(shdr_buf[56..64].try_into().unwrap());

        let sh_flags = Elf64ShdrFlags::from_bits_truncate(sh_flags);

        Self {
            sh_name,
            sh_type,
            sh_flags,
            sh_addr,
            sh_offset,
            sh_size,
            sh_link,
            sh_info,
            sh_addralign,
            sh_entsize,
        }
    }

    fn verify(&self) -> Result<(), ElfError> {
        if self.sh_type == Self::SHT_NULL {
            return Ok(());
        }

        if self.sh_type != Self::SHT_NOBITS {
            Elf64FileRange::try_from((self.sh_offset, self.sh_size))?;
        } else {
            Elf64FileRange::try_from((self.sh_offset, 0))?;
        }

        if self.sh_flags.contains(Elf64ShdrFlags::ALLOC) {
            Elf64AddrRange::try_from((self.sh_addr, self.sh_size))?;

            if self.sh_addralign != 0 {
                if self.sh_addralign != 0 && !self.sh_addralign.is_power_of_two() {
                    return Err(ElfError::InvalidAddressAlignment);
                }
                if self.sh_addr & (self.sh_addralign - 1) != 0 {
                    return Err(ElfError::InvalidAddressAlignment);
                }
            }
        } else if self.sh_addr != 0 {
            return Err(ElfError::InvalidAddressRange);
        }

        Ok(())
    }

    fn file_range(&self) -> Elf64FileRange {
        if self.sh_type != Self::SHT_NOBITS {
            Elf64FileRange::try_from((self.sh_offset, self.sh_size)).unwrap()
        } else {
            Elf64FileRange::try_from((self.sh_offset, 0)).unwrap()
        }
    }
}

#[derive(Debug)]
struct Elf64LoadSegments {
    segments: Vec<(Elf64AddrRange, Elf64Half)>,
}

impl Elf64LoadSegments {
    fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    fn find_first_not_before(&self, range: &Elf64AddrRange) -> Option<usize> {
        let i = self.segments.partition_point(|segment| {
            matches!(segment.0.partial_cmp(range), Some(cmp::Ordering::Less))
        });

        if i != self.segments.len() {
            Some(i)
        } else {
            None
        }
    }

    fn try_insert(&mut self, segment: Elf64AddrRange, phdr_index: Elf64Half) -> Result<(), ()> {
        let i = self.find_first_not_before(&segment);
        match i {
            Some(i) => {
                match segment.partial_cmp(&self.segments[i].0) {
                    Some(cmp::Ordering::Less) => {
                        // Ok, no overlap.
                        self.segments.insert(i, (segment, phdr_index));
                        Ok(())
                    }
                    _ => Err(()),
                }
            }
            None => {
                self.segments.push((segment, phdr_index));
                Ok(())
            }
        }
    }

    fn lookup_vaddr_range(&self, range: &Elf64AddrRange) -> Option<(Elf64Half, Elf64Xword)> {
        let i = self.find_first_not_before(range);
        let i = match i {
            Some(i) => i,
            None => return None,
        };

        let segment = &self.segments[i];
        if segment.0.vaddr_begin <= range.vaddr_begin && range.vaddr_end <= segment.0.vaddr_end {
            let offset_in_segment = range.vaddr_begin - segment.0.vaddr_begin;
            Some((segment.1, offset_in_segment))
        } else {
            None
        }
    }

    fn total_vaddr_range(&self) -> Elf64AddrRange {
        Elf64AddrRange {
            vaddr_begin: self.segments.first().map_or(0, |first| first.0.vaddr_begin),
            vaddr_end: self.segments.last().map_or(0, |last| last.0.vaddr_end),
        }
    }
}

#[derive(Debug)]
struct Elf64DynamicRelocTable {
    base_vaddr: Elf64Addr, // DT_RELA / DT_REL
    size: Elf64Xword,      // DT_RELASZ / DT_RELSZ
    entsize: Elf64Xword,   // DT_RELAENT / DT_RELENT
}

impl Elf64DynamicRelocTable {
    fn verify(&self) -> Result<(), ElfError> {
        Elf64AddrRange::try_from((self.base_vaddr, self.size))?;
        Ok(())
    }

    fn vaddr_range(&self) -> Elf64AddrRange {
        Elf64AddrRange::try_from((self.base_vaddr, self.size)).unwrap()
    }
}

#[derive(Debug)]
struct Elf64DynamicSymtab {
    base_vaddr: Elf64Addr, // DT_SYMTAB
    entsize: Elf64Xword,   // DT_SYMENT
    #[allow(unused)]
    shndx: Option<Elf64Addr>, // DT_SYMTAB_SHNDX
}

impl Elf64DynamicSymtab {
    fn verify(&self) -> Result<(), ElfError> {
        Ok(())
    }
}

#[derive(Debug)]
struct Elf64Dynamic {
    // No DT_REL representation: "The AMD64 ABI architectures uses only
    // Elf64_Rela relocation entries [...]".
    rela: Option<Elf64DynamicRelocTable>,
    symtab: Option<Elf64DynamicSymtab>,
    flags_1: Elf64Xword,
}

impl Elf64Dynamic {
    const DT_NULL: Elf64Xword = 0;
    const DT_HASH: Elf64Xword = 4;
    const DT_STRTAB: Elf64Xword = 5;
    const DT_SYMTAB: Elf64Xword = 6;
    const DT_RELA: Elf64Xword = 7;
    const DT_RELASZ: Elf64Xword = 8;
    const DT_RELAENT: Elf64Xword = 9;
    const DT_STRSZ: Elf64Xword = 10;
    const DT_SYMENT: Elf64Xword = 11;
    const DT_DEBUG: Elf64Xword = 21;
    const DT_TEXTREL: Elf64Xword = 22;
    const DT_FLAGS: Elf64Xword = 30;
    const DT_SYMTAB_SHNDX: Elf64Xword = 34;
    const DT_GNU_HASH: Elf64Xword = 0x6ffffef5;
    const DT_RELACOUNT: Elf64Xword = 0x6ffffff9;
    const DT_FLAGS_1: Elf64Xword = 0x6ffffffb;

    const DF_PIE_1: Elf64Xword = 0x08000000;

    fn read(buf: &[u8]) -> Result<Self, ElfError> {
        let mut rela: Option<Elf64Addr> = None;
        let mut relasz: Option<Elf64Xword> = None;
        let mut relaent: Option<Elf64Xword> = None;

        let mut symtab: Option<Elf64Addr> = None;
        let mut syment: Option<Elf64Xword> = None;
        let mut symtab_shndx: Option<Elf64Addr> = None;

        let mut flags_1: Option<Elf64Xword> = None;

        let mut fields = [
            (Self::DT_RELA, &mut rela),
            (Self::DT_RELASZ, &mut relasz),
            (Self::DT_RELAENT, &mut relaent),
            (Self::DT_SYMTAB, &mut symtab),
            (Self::DT_SYMENT, &mut syment),
            (Self::DT_SYMTAB_SHNDX, &mut symtab_shndx),
            (Self::DT_FLAGS_1, &mut flags_1),
        ];
        let ignored_fields = [
            Self::DT_HASH,
            Self::DT_STRTAB,
            Self::DT_STRSZ,
            Self::DT_DEBUG,
            Self::DT_TEXTREL,
            Self::DT_FLAGS,
            Self::DT_GNU_HASH,
            Self::DT_RELACOUNT,
        ];
        let mut null_seen = false;
        for entry_buf in buf.chunks(16) {
            let d_tag = Elf64Xword::from_le_bytes(entry_buf[0..8].try_into().unwrap());

            if d_tag == Self::DT_NULL {
                null_seen = true;
                break;
            }

            if let Some(field) = fields.iter_mut().find(|f| f.0 == d_tag) {
                if field.1.is_some() {
                    return Err(ElfError::DynamicFieldConflict);
                }

                let d_val = Elf64Xword::from_le_bytes(entry_buf[8..16].try_into().unwrap());
                *field.1 = Some(d_val);
            } else if ignored_fields.iter().all(|tag| *tag != d_tag) {
                // For unhandled fields not on the ignore list, bail out:
                // failing to take the associated, required fixup action from
                // the dynamic loader, if any, would result in a broken image,
                // respectively in hard to debug runtime breakages.
                return Err(ElfError::UnrecognizedDynamicField);
            }
        }
        if !null_seen {
            return Err(ElfError::UnterminatedDynamicSection);
        }

        let rela = if rela.is_some() || relasz.is_some() || relaent.is_some() {
            let rela = rela.ok_or(ElfError::MissingDynamicField)?;
            let relasz = relasz.ok_or(ElfError::MissingDynamicField)?;
            let relaent = relaent.ok_or(ElfError::MissingDynamicField)?;
            Some(Elf64DynamicRelocTable {
                base_vaddr: rela,
                size: relasz,
                entsize: relaent,
            })
        } else {
            None
        };

        let symtab = if symtab.is_some() || syment.is_some() {
            let symtab = symtab.ok_or(ElfError::MissingDynamicField)?;
            let syment = syment.ok_or(ElfError::MissingDynamicField)?;
            Some(Elf64DynamicSymtab {
                base_vaddr: symtab,
                entsize: syment,
                shndx: symtab_shndx,
            })
        } else {
            None
        };

        let flags_1 = flags_1.unwrap_or(0);

        Ok(Elf64Dynamic {
            rela,
            symtab,
            flags_1,
        })
    }

    fn verify(&self) -> Result<(), ElfError> {
        if let Some(rela) = &self.rela {
            rela.verify()?;
        }
        if let Some(symtab) = &self.symtab {
            symtab.verify()?;
        }
        Ok(())
    }

    fn is_pie(&self) -> bool {
        self.flags_1 & Self::DF_PIE_1 != 0
    }
}

pub struct Elf64ImageLoadVaddrAllocInfo {
    pub range: Elf64AddrRange,     // vaddr range to allocate
    pub align: Option<Elf64Xword>, // Set for PIE executables so that a valid vaddr base can be allocated.
}

pub struct Elf64ImageLoadSegment<'a> {
    pub vaddr_range: Elf64AddrRange,
    pub file_contents: &'a [u8],
    pub flags: Elf64PhdrFlags,
}

pub struct Elf64ImageLoadSegmentIterator<'a> {
    elf_file: &'a Elf64File<'a>,
    load_base: Elf64Xword,

    next: usize,
}

impl<'a> Iterator for Elf64ImageLoadSegmentIterator<'a> {
    type Item = Elf64ImageLoadSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.next;
        if cur == self.elf_file.load_segments.segments.len() {
            return None;
        }
        self.next += 1;

        let phdr_index = self.elf_file.load_segments.segments[cur].1;
        let phdr = self.elf_file.read_phdr(phdr_index);

        let mut vaddr_range = phdr.vaddr_range();
        vaddr_range.vaddr_begin = vaddr_range.vaddr_begin.wrapping_add(self.load_base);
        vaddr_range.vaddr_end = vaddr_range.vaddr_end.wrapping_add(self.load_base);

        let file_range = phdr.file_range();
        let file_contents =
            &self.elf_file.elf_file_buf[file_range.offset_begin..file_range.offset_end];

        Some(Elf64ImageLoadSegment {
            vaddr_range,
            file_contents,
            flags: phdr.p_flags,
        })
    }
}

struct Elf64Strtab<'a> {
    strtab_buf: &'a [u8],
}

impl<'a> Elf64Strtab<'a> {
    fn new(strtab_buf: &'a [u8]) -> Self {
        Self { strtab_buf }
    }

    #[allow(unused)]
    fn get_str(&self, index: Elf64Word) -> Result<&'a ffi::CStr, ElfError> {
        let index = usize::try_from(index).unwrap();
        if index >= self.strtab_buf.len() {
            return Err(ElfError::InvalidStrtabString);
        }

        ffi::CStr::from_bytes_until_nul(&self.strtab_buf[index..])
            .map_err(|_| ElfError::InvalidStrtabString)
    }
}

#[derive(Debug)]
struct Elf64Sym {
    #[allow(unused)]
    st_name: Elf64Word,
    #[allow(unused)]
    st_info: Elf64char,
    #[allow(unused)]
    st_other: Elf64char,
    st_shndx: Elf64Half,
    st_value: Elf64Addr,
    #[allow(unused)]
    st_size: Elf64Xword,
}

impl Elf64Sym {
    fn read(buf: &[u8]) -> Self {
        let st_name = Elf64Word::from_le_bytes(buf[0..4].try_into().unwrap());
        let st_info = Elf64char::from_le_bytes(buf[4..5].try_into().unwrap());
        let st_other = Elf64char::from_le_bytes(buf[5..6].try_into().unwrap());
        let st_shndx = Elf64Half::from_le_bytes(buf[6..8].try_into().unwrap());
        let st_value = Elf64Addr::from_le_bytes(buf[8..16].try_into().unwrap());
        let st_size = Elf64Xword::from_le_bytes(buf[16..24].try_into().unwrap());
        Self {
            st_name,
            st_info,
            st_other,
            st_shndx,
            st_value,
            st_size,
        }
    }
}

struct Elf64Symtab<'a> {
    syms_buf: &'a [u8],
    entsize: usize,
    syms_num: Elf64Word,
}

impl<'a> Elf64Symtab<'a> {
    const STN_UNDEF: Elf64Word = 0;

    fn new(syms_buf: &'a [u8], entsize: Elf64Xword) -> Result<Self, ElfError> {
        let entsize = usize::try_from(entsize).map_err(|_| ElfError::InvalidSymbolEntrySize)?;
        if entsize < 24 {
            return Err(ElfError::InvalidSymbolEntrySize);
        }
        let syms_num = syms_buf.len() / entsize;
        let syms_num = Elf64Word::try_from(syms_num).map_err(|_| ElfError::InvalidSymbolIndex)?;
        Ok(Self {
            syms_buf,
            entsize,
            syms_num,
        })
    }

    fn read_sym(&self, i: Elf64Word) -> Result<Elf64Sym, ElfError> {
        if i > self.syms_num {
            return Err(ElfError::InvalidSymbolIndex);
        }
        let i = usize::try_from(i).map_err(|_| ElfError::InvalidSymbolIndex)?;
        let sym_off = i * self.entsize;
        let sym_buf = &self.syms_buf[sym_off..(sym_off + self.entsize)];
        Ok(Elf64Sym::read(sym_buf))
    }
}

#[derive(Debug)]
pub struct Elf64Rela {
    r_offset: Elf64Addr,
    r_info: Elf64Xword,
    r_addend: Elf64Sxword,
}

impl Elf64Rela {
    fn get_sym(&self) -> Elf64Word {
        (self.r_info >> 32) as Elf64Word
    }

    fn get_type(&self) -> Elf64Word {
        (self.r_info & 0xffffffffu64) as Elf64Word
    }

    fn read(rela_buf: &[u8]) -> Self {
        let r_offset = Elf64Addr::from_le_bytes(rela_buf[0..8].try_into().unwrap());
        let r_info = Elf64Xword::from_le_bytes(rela_buf[8..16].try_into().unwrap());
        let r_addend = Elf64Sxword::from_le_bytes(rela_buf[16..24].try_into().unwrap());
        Self {
            r_offset,
            r_info,
            r_addend,
        }
    }
}

struct Elf64Relas<'a> {
    relas_buf: &'a [u8],
    entsize: usize,
    relas_num: usize,
}

impl<'a> Elf64Relas<'a> {
    fn new(relas_buf: &'a [u8], entsize: Elf64Xword) -> Result<Self, ElfError> {
        let entsize = usize::try_from(entsize).map_err(|_| ElfError::InvalidRelocationEntrySize)?;
        if entsize < 24 {
            return Err(ElfError::InvalidRelocationEntrySize);
        }
        let relas_num = relas_buf.len() / entsize;
        Ok(Self {
            relas_buf,
            entsize,
            relas_num,
        })
    }

    fn read_rela(&self, i: usize) -> Result<Elf64Rela, ElfError> {
        let rela_off = i * self.entsize;
        let rela_buf = &self.relas_buf[rela_off..(rela_off + self.entsize)];
        Ok(Elf64Rela::read(rela_buf))
    }
}

pub struct Elf64ShdrIterator<'a> {
    elf_file: &'a Elf64File<'a>,
    next: Elf64Word,
}

impl<'a> Elf64ShdrIterator<'a> {
    fn new(elf_file: &'a Elf64File<'a>) -> Self {
        Self { elf_file, next: 0 }
    }
}

impl<'a> Iterator for Elf64ShdrIterator<'a> {
    type Item = Elf64Shdr;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.next;
        if cur == self.elf_file.elf_hdr.e_shnum {
            return None;
        }
        self.next += 1;
        Some(self.elf_file.read_shdr(cur))
    }
}

#[derive(Debug)]
pub struct Elf64RelocOp {
    pub dst: Elf64Addr,
    pub value: [u8; 8],
    pub value_len: usize,
}

pub trait Elf64RelocProcessor {
    fn apply_relocation(
        &self,
        rela: &Elf64Rela,
        load_base: Elf64Xword,
        sym_value: Elf64Addr,
    ) -> Result<Elf64RelocOp, ElfError>;
}

pub struct Elf64X86RelocProcessor;

impl Elf64X86RelocProcessor {
    const R_X86_64_64: Elf64Word = 1;
    const R_X86_64_PC32: Elf64Word = 2;
    const R_X86_64_RELATIVE: Elf64Word = 8;
    const R_X86_64_32: Elf64Word = 10;
    const R_X86_64_32S: Elf64Word = 11;
    const R_X86_64_PC64: Elf64Word = 24;

    pub fn new() -> Self {
        Self
    }
}

impl Default for Elf64X86RelocProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl Elf64RelocProcessor for Elf64X86RelocProcessor {
    fn apply_relocation(
        &self,
        rela: &Elf64Rela,
        load_base: Elf64Xword,
        sym_value: Elf64Addr,
    ) -> Result<Elf64RelocOp, ElfError> {
        // load_base is the difference between the actual mapping addresses
        // and the ELF vaddrs. This signed difference is represented in
        // two's complement.
        let p = rela.r_offset.wrapping_add(load_base);
        // Use two's complement arithmethic for the addend.
        let a = rela.r_addend as u64;
        let (value, value_len) = match rela.get_type() {
            Self::R_X86_64_64 => {
                let value = sym_value.wrapping_add(a);
                (value, 8)
            }
            Self::R_X86_64_PC32 => {
                let value = sym_value.wrapping_add(a);
                let value = value.wrapping_sub(p);
                (value, 4)
            }
            Self::R_X86_64_RELATIVE => {
                let value = load_base.wrapping_add(a);
                (value, 8)
            }
            Self::R_X86_64_32 => {
                let value = sym_value.wrapping_add(a);
                (value, 4)
            }
            Self::R_X86_64_32S => {
                let value = sym_value.wrapping_add(a);
                (value, 4)
            }
            Self::R_X86_64_PC64 => {
                let value = sym_value.wrapping_add(a);
                let value = value.wrapping_sub(p);
                (value, 8)
            }
            _ => return Err(ElfError::UnrecognizedRelocationType),
        };

        let value = value.to_le_bytes();
        Ok(Elf64RelocOp {
            dst: p,
            value,
            value_len,
        })
    }
}

pub struct Elf64AppliedRelaIterator<'a, RP: Elf64RelocProcessor> {
    rela_proc: RP,
    load_base: Elf64Xword,

    load_segments: &'a Elf64LoadSegments,

    relas: Elf64Relas<'a>,
    symtab: Option<Elf64Symtab<'a>>,

    next: usize,
}

impl<'a, RP: Elf64RelocProcessor> Elf64AppliedRelaIterator<'a, RP> {
    fn new(
        rela_proc: RP,
        load_base: Elf64Xword,
        load_segments: &'a Elf64LoadSegments,
        relas: Elf64Relas<'a>,
        symtab: Option<Elf64Symtab<'a>>,
    ) -> Self {
        Self {
            rela_proc,
            load_base,
            load_segments,
            relas,
            symtab,
            next: 0,
        }
    }
}

impl<'a, RP: Elf64RelocProcessor> Iterator for Elf64AppliedRelaIterator<'a, RP> {
    type Item = Result<Option<Elf64RelocOp>, ElfError>;

    fn next(&mut self) -> Option<Self::Item> {
        let cur = self.next;
        if cur == self.relas.relas_num {
            return None;
        }
        self.next += 1;

        let rela = match self.relas.read_rela(cur) {
            Ok(rela) => rela,
            Err(e) => return Some(Err(e)),
        };

        if rela.get_type() == 0 {
            return Some(Ok(None));
        }

        let sym_index = rela.get_sym();
        let sym_value = if sym_index != Elf64Symtab::STN_UNDEF {
            let symtab = match &self.symtab {
                Some(symtab) => symtab,
                None => return Some(Err(ElfError::InvalidSymbolIndex)),
            };
            let sym = match symtab.read_sym(sym_index) {
                Ok(sym) => sym,
                Err(e) => return Some(Err(e)),
            };

            if sym.st_shndx as Elf64Word == Elf64Shdr::SHN_UNDEF {
                return Some(Err(ElfError::RelocationAgainstUndefSymbol));
            } else if sym.st_shndx as Elf64Word == Elf64Shdr::SHN_ABS {
                // Absolute symbol, no adjustment by load_base.
                sym.st_value
            } else {
                // load_base is the difference between the actual mapping
                // addresses and the ELF vaddrs. This signed difference is
                // represented in two's complement.
                sym.st_value.wrapping_add(self.load_base)
            }
        } else {
            0
        };

        let reloc_op = match self
            .rela_proc
            .apply_relocation(&rela, self.load_base, sym_value)
        {
            Ok(reloc_op) => reloc_op,
            Err(e) => return Some(Err(e)),
        };

        // Check that the write destination is contained within one of the
        // PT_LOAD segments, so that the consumer won't write the result into
        // nowhere.
        let dst_vaddr_begin = rela.r_offset;
        let dst_vaddr_end = match dst_vaddr_begin.checked_add(reloc_op.value_len as Elf64Xword) {
            Some(dst_end) => dst_end,
            None => return Some(Err(ElfError::InvalidAddressRange)),
        };
        let dst_vaddr_range = Elf64AddrRange {
            vaddr_begin: dst_vaddr_begin,
            vaddr_end: dst_vaddr_end,
        };
        if self
            .load_segments
            .lookup_vaddr_range(&dst_vaddr_range)
            .is_none()
        {
            return Some(Err(ElfError::InvalidRelocationOffset));
        }

        Some(Ok(Some(reloc_op)))
    }
}
