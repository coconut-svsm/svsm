// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2023-2024 SUSE LLC
//
// Author: Nicolai Stange <nstange@suse.de>
//
// vim: ts=4 sw=4 et

use super::*;

#[test]
fn test_elf64_shdr_verify_methods() {
    // Create a valid Elf64Shdr instance for testing.
    let valid_shdr = Elf64Shdr {
        sh_name: 1,
        sh_type: 2,
        sh_flags: Elf64ShdrFlags::WRITE | Elf64ShdrFlags::ALLOC,
        sh_addr: 0x1000,
        sh_offset: 0x2000,
        sh_size: 0x3000,
        sh_link: 3,
        sh_info: 4,
        sh_addralign: 8,
        sh_entsize: 0,
    };

    // Verify that the valid Elf64Shdr instance passes verification.
    assert!(valid_shdr.verify().is_ok());

    // Create an invalid Elf64Shdr instance for testing.
    let invalid_shdr = Elf64Shdr {
        sh_name: 0,
        sh_type: 2,
        sh_flags: Elf64ShdrFlags::from_bits(0).unwrap(),
        sh_addr: 0x1000,
        sh_offset: 0x2000,
        sh_size: 0x3000,
        sh_link: 3,
        sh_info: 4,
        sh_addralign: 7, // Invalid alignment
        sh_entsize: 0,
    };

    // Verify that the invalid Elf64Shdr instance fails verification.
    assert!(invalid_shdr.verify().is_err());
}

#[test]
fn test_elf64_dynamic_reloc_table_verify_valid() {
    // Create a valid Elf64DynamicRelocTable instance for testing.
    let reloc_table = Elf64DynamicRelocTable {
        base_vaddr: 0x1000,
        size: 0x2000,
        entsize: 0x30,
    };

    // Verify that the valid Elf64DynamicRelocTable instance passes verification.
    assert!(reloc_table.verify().is_ok());
}

#[test]
fn test_elf64_addr_range_methods() {
    // Test Elf64AddrRange::len() and Elf64AddrRange::is_empty().

    // Create an Elf64AddrRange instance for testing.
    let addr_range = Elf64AddrRange {
        vaddr_begin: 0x1000,
        vaddr_end: 0x2000,
    };

    // Check that the length calculation is correct.
    assert_eq!(addr_range.len(), 0x1000);

    // Check if the address range is empty.
    assert!(!addr_range.is_empty());

    // Test Elf64AddrRange::try_from().

    // Create a valid input tuple for try_from.
    let valid_input: (Elf64Addr, Elf64Xword) = (0x1000, 0x2000);

    // Attempt to create an Elf64AddrRange from the valid input.
    let result = Elf64AddrRange::try_from(valid_input);

    // Verify that the result is Ok and contains the expected Elf64AddrRange.
    assert!(result.is_ok());
    let valid_addr_range = result.unwrap();
    assert_eq!(valid_addr_range.vaddr_begin, 0x1000);
    assert_eq!(valid_addr_range.vaddr_end, 0x3000);
}

#[test]
fn test_elf64_file_range_try_from() {
    // Valid range
    let valid_range: (Elf64Off, Elf64Xword) = (0, 100);
    let result: Result<Elf64FileRange, ElfError> = valid_range.try_into();
    assert!(result.is_ok());
    let file_range = result.unwrap();
    assert_eq!(file_range.offset_begin, 0);
    assert_eq!(file_range.offset_end, 100);

    // Invalid range (overflow)
    let invalid_range: (Elf64Off, Elf64Xword) = (usize::MAX as Elf64Off, 100);
    let result: Result<Elf64FileRange, ElfError> = invalid_range.try_into();
    assert!(result.is_err());
}

#[test]
fn test_elf64_file_read() {
    // In the future, you can play around with this skeleton ELF
    // file to test other cases
    let byte_data: [u8; 184] = [
        // ELF Header
        0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // Program Header (with PT_LOAD)
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // Section Header (simplified)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // Raw Machine Code Instructions
        0xf3, 0x0f, 0x1e, 0xfa, 0x31, 0xed, 0x49, 0x89, 0xd1, 0x5e, 0x48, 0x89, 0xe2, 0x48, 0x83,
        0xe4, 0xf0, 0x50, 0x54, 0x45, 0x31, 0xc0, 0x31, 0xc9, 0x48, 0x8d, 0x3d, 0xca, 0x00, 0x00,
        0x00, 0xff, 0x15, 0x53, 0x2f, 0x00, 0x00, 0xf4, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00,
        0x00, 0x00, 0x48, 0x8d, 0x3d, 0x79, 0x2f, 0x00, 0x00, 0x48, 0x8d, 0x05, 0x72, 0x2f, 0x00,
        0x00, 0x48, 0x39, 0xf8, 0x74, 0x15, 0x48, 0x8b, 0x05, 0x36, 0x2f, 0x00, 0x00, 0x48, 0x85,
        0xc0, 0x74, 0x09, 0xff, 0xe0, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, 0xc3,
    ];

    // Use the Elf64File::read method to create an Elf64File instance
    let res = Elf64File::read(&byte_data);
    assert_eq!(res, Err(ElfError::InvalidPhdrSize));

    // Construct an Elf64Hdr instance from the byte data
    let elf_hdr = Elf64Hdr::read(&byte_data);

    // Did we fail to read the ELF header?
    assert!(elf_hdr.is_ok());
    let elf_hdr = elf_hdr.unwrap();

    let expected_type = 2;
    let expected_machine = 0x3E;
    let expected_version = 1;

    // Assert that the fields of the header match the expected values
    assert_eq!(elf_hdr.e_type, expected_type);
    assert_eq!(elf_hdr.e_machine, expected_machine);
    assert_eq!(elf_hdr.e_version, expected_version);
}

#[test]
fn test_elf64_load_segments() {
    let mut load_segments = Elf64LoadSegments::new();
    let vaddr_range1 = Elf64AddrRange {
        vaddr_begin: 0x1000,
        vaddr_end: 0x2000,
    };
    let vaddr_range2 = Elf64AddrRange {
        vaddr_begin: 0x3000,
        vaddr_end: 0x4000,
    };
    let segment_index1 = 0;
    let segment_index2 = 1;

    // Insert load segments
    assert!(
        load_segments
            .try_insert(vaddr_range1, segment_index1)
            .is_ok()
    );
    assert!(
        load_segments
            .try_insert(vaddr_range2, segment_index2)
            .is_ok()
    );

    // Lookup load segments by virtual address
    let (index1, offset1) = load_segments
        .lookup_vaddr_range(&Elf64AddrRange {
            vaddr_begin: 0x1500,
            vaddr_end: 0x1700,
        })
        .unwrap();
    let (index2, offset2) = load_segments
        .lookup_vaddr_range(&Elf64AddrRange {
            vaddr_begin: 0x3500,
            vaddr_end: 0x3700,
        })
        .unwrap();

    assert_eq!(index1, segment_index1);
    assert_eq!(offset1, 0x500); // Offset within the segment
    assert_eq!(index2, segment_index2);
    assert_eq!(offset2, 0x500); // Offset within the segment

    // Total virtual address range
    let total_range = load_segments.total_vaddr_range();
    assert_eq!(total_range.vaddr_begin, 0x1000);
    assert_eq!(total_range.vaddr_end, 0x4000);
}

const TEST_ELF_HDR_SIZE: usize = 64;
const TEST_PHDR_SIZE: usize = 56;

/// Writes a minimal valid 64-bit little-endian ELF header for an ET_EXEC
/// x86-64 file with `phnum` program headers immediately following the header.
fn write_test_elf_hdr(buf: &mut [u8], phnum: u16) {
    buf[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine = EM_X86_64
    buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version = EV_CURRENT
    buf[24..32].copy_from_slice(&0x1000u64.to_le_bytes()); // e_entry
    buf[32..40].copy_from_slice(&(TEST_ELF_HDR_SIZE as u64).to_le_bytes()); // e_phoff
    buf[52..54].copy_from_slice(&(TEST_ELF_HDR_SIZE as u16).to_le_bytes()); // e_ehsize
    buf[54..56].copy_from_slice(&(TEST_PHDR_SIZE as u16).to_le_bytes()); // e_phentsize
    buf[56..58].copy_from_slice(&phnum.to_le_bytes()); // e_phnum
    buf[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
}

/// Writes a program header with the given type, vaddr and memsz. The segment
/// has no file backing (p_filesz = 0) and no alignment constraints
/// (p_align = 1).
fn write_test_phdr(buf: &mut [u8], p_type: Elf64Word, vaddr: Elf64Addr, memsz: Elf64Xword) {
    buf[..4].copy_from_slice(&p_type.to_le_bytes());
    buf[4..8].copy_from_slice(&4u32.to_le_bytes()); // p_flags = PF_R
    buf[16..24].copy_from_slice(&vaddr.to_le_bytes()); // p_vaddr
    buf[40..48].copy_from_slice(&memsz.to_le_bytes()); // p_memsz
    buf[48..56].copy_from_slice(&1u64.to_le_bytes()); // p_align
}

#[test]
fn test_elf64_relro_range() {
    let mut byte_data = [0u8; TEST_ELF_HDR_SIZE + 2 * TEST_PHDR_SIZE];
    write_test_elf_hdr(&mut byte_data, 2);
    let (load_phdr, relro_phdr) = byte_data[TEST_ELF_HDR_SIZE..].split_at_mut(TEST_PHDR_SIZE);
    write_test_phdr(load_phdr, Elf64Phdr::PT_LOAD, 0x1000, 0x2000);
    write_test_phdr(relro_phdr, Elf64Phdr::PT_GNU_RELRO, 0x1000, 0x500);

    let elf = Elf64File::read(&byte_data).expect("Failed to parse test ELF file");
    assert_eq!(
        elf.relro_vaddr_range,
        Some(Elf64AddrRange {
            vaddr_begin: 0x1000,
            vaddr_end: 0x1500,
        })
    );

    // Image loaded at the link-time address: no adjustment.
    assert_eq!(
        elf.image_relro_vaddr_range(0x1000),
        Some(Elf64AddrRange {
            vaddr_begin: 0x1000,
            vaddr_end: 0x1500,
        })
    );

    // Image loaded at a different address: range adjusted by the load base.
    assert_eq!(
        elf.image_relro_vaddr_range(0x9000),
        Some(Elf64AddrRange {
            vaddr_begin: 0x9000,
            vaddr_end: 0x9500,
        })
    );
}

#[test]
fn test_elf64_relro_range_empty() {
    // An empty (p_memsz = 0) PT_GNU_RELRO segment is rejected.
    let mut byte_data = [0u8; TEST_ELF_HDR_SIZE + 2 * TEST_PHDR_SIZE];
    write_test_elf_hdr(&mut byte_data, 2);
    let (load_phdr, relro_phdr) = byte_data[TEST_ELF_HDR_SIZE..].split_at_mut(TEST_PHDR_SIZE);
    write_test_phdr(load_phdr, Elf64Phdr::PT_LOAD, 0x1000, 0x2000);
    write_test_phdr(relro_phdr, Elf64Phdr::PT_GNU_RELRO, 0x1000, 0);

    let res = Elf64File::read(&byte_data);
    assert_eq!(res, Err(ElfError::InvalidSegmentSize));
}

#[test]
fn test_elf64_relro_range_absent() {
    let mut byte_data = [0u8; TEST_ELF_HDR_SIZE + TEST_PHDR_SIZE];
    write_test_elf_hdr(&mut byte_data, 1);
    write_test_phdr(
        &mut byte_data[TEST_ELF_HDR_SIZE..],
        Elf64Phdr::PT_LOAD,
        0x1000,
        0x2000,
    );

    let elf = Elf64File::read(&byte_data).expect("Failed to parse test ELF file");
    assert_eq!(elf.relro_vaddr_range, None);
    assert_eq!(elf.image_relro_vaddr_range(0x1000), None);
}

#[test]
fn test_elf64_relro_phdr_conflict() {
    // Multiple PT_GNU_RELRO program headers are rejected.
    let mut byte_data = [0u8; TEST_ELF_HDR_SIZE + 3 * TEST_PHDR_SIZE];
    write_test_elf_hdr(&mut byte_data, 3);
    let (load_phdr, rest) = byte_data[TEST_ELF_HDR_SIZE..].split_at_mut(TEST_PHDR_SIZE);
    let (relro_phdr0, relro_phdr1) = rest.split_at_mut(TEST_PHDR_SIZE);
    write_test_phdr(load_phdr, Elf64Phdr::PT_LOAD, 0x1000, 0x2000);
    write_test_phdr(relro_phdr0, Elf64Phdr::PT_GNU_RELRO, 0x1000, 0x500);
    write_test_phdr(relro_phdr1, Elf64Phdr::PT_GNU_RELRO, 0x1500, 0x500);

    let res = Elf64File::read(&byte_data);
    assert_eq!(res, Err(ElfError::RelroPhdrConflict));
}
