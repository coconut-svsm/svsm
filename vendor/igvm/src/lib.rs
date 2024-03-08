// SPDX-License-Identifier: MIT
//
// Copyright (c) Microsoft Corporation.

//! Provides a Rust implementation of an Independent Guest Virtual Machine
//! (IGVM) file format parser, with the specification defined by the
//! [`igvm_defs`] crate.
//!
//! This can be used to build or read IGVM files from their binary format. Note
//! that this parser may not implement all the specified structure types or
//! semantics defined in the IGVM file format.

#![deny(unsafe_code)]
// Enables the `doc_cfg` feature when the `docsrs` configuration attribute
// is defined.
#![cfg_attr(docsrs, feature(doc_cfg))]

use hv_defs::HvArm64RegisterName;
use hv_defs::HvX64RegisterName;
use hv_defs::Vtl;
use igvm_defs::*;
use page_table::PageTableRelocationBuilder;
use parsing::FromBytesExt;
use range_map_vec::RangeMap;
use registers::AArch64Register;
use registers::X86Register;
use snp_defs::SevVmsa;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt;
use std::mem::size_of;
use std::mem::size_of_val;
use thiserror::Error;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

#[cfg(feature = "igvm-c")]
pub mod c_api;

pub mod hv_defs;
pub mod page_table;
mod parsing;
pub mod registers;
pub mod snp_defs;

// Define type alias for no padding u64.
#[allow(non_camel_case_types)]
type u64_le = zerocopy::U64<zerocopy::LittleEndian>;

/// The guest isolation type of the platform.
#[derive(Debug, PartialEq, Eq)]
pub enum IsolationType {
    /// This guest is isolated with VBS.
    Vbs,
    /// This guest is isolated with SNP (physical or emulated).
    Snp,
    /// This guest is isolated with TDX (physical or emulated).
    Tdx,
}

impl From<IsolationType> for igvm_defs::IgvmPlatformType {
    fn from(typ: IsolationType) -> Self {
        match typ {
            IsolationType::Vbs => IgvmPlatformType::VSM_ISOLATION,
            IsolationType::Snp => IgvmPlatformType::SEV_SNP,
            IsolationType::Tdx => IgvmPlatformType::TDX,
        }
    }
}

/// Align x up to the next multiple of 8.
fn align_8(x: usize) -> usize {
    (x + 7) & !7
}

/// Helper function to parse the given type from a byte slice, updating the
/// passed in slice with the remaining bytes left.
///
/// On failure, returns [`BinaryHeaderError::InvalidVariableHeaderSize`].
fn read_header<T: FromBytesExt>(bytes: &mut &[u8]) -> Result<T, BinaryHeaderError> {
    T::read_from_prefix_split(bytes)
        .ok_or(BinaryHeaderError::InvalidVariableHeaderSize)
        .map(|(header, remaining)| {
            *bytes = remaining;
            header
        })
}

/// Helper function to append a given binary header to a variable header
/// section.
fn append_header<T: AsBytes>(
    header: &T,
    header_type: IgvmVariableHeaderType,
    variable_headers: &mut Vec<u8>,
) {
    let header = header.as_bytes();

    // Append the fixed header first. The fixed header must correctly describe
    // the length of the structure, but the structure may not be aligned to 8
    // bytes. Variable headers must be 8 byte aligned as defined by the spec, so
    // insert any padding bytes as needed.
    let fixed_header = IGVM_VHS_VARIABLE_HEADER {
        typ: header_type,
        length: header
            .len()
            .try_into()
            .expect("header data must fit in u32"),
    };

    let align_up_iter = std::iter::repeat(&0u8).take(align_8(header.len()) - header.len());

    variable_headers.extend_from_slice(fixed_header.as_bytes());
    variable_headers.extend_from_slice(header);
    variable_headers.extend(align_up_iter);

    debug_assert!(variable_headers.len() % 8 == 0);
}

/// Represents a structure in an IGVM variable header section, platform
/// structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgvmPlatformHeader {
    SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM),
}

impl IgvmPlatformHeader {
    /// Get the in file variable header size of the given type.
    fn header_size(&self) -> usize {
        let additional = match self {
            IgvmPlatformHeader::SupportedPlatform(platform) => size_of_val(platform),
        };

        size_of::<IGVM_VHS_VARIABLE_HEADER>() + additional
    }

    /// Get the [`IgvmVariableHeaderType`] for the platform header.
    #[cfg(feature = "igvm-c")]
    #[cfg_attr(docsrs, doc(cfg(feature = "igvm-c")))]
    fn header_type(&self) -> IgvmVariableHeaderType {
        match self {
            IgvmPlatformHeader::SupportedPlatform(_) => {
                IgvmVariableHeaderType::IGVM_VHT_SUPPORTED_PLATFORM
            }
        }
    }

    /// Checks if this header contains valid state.
    fn validate(&self) -> Result<(), BinaryHeaderError> {
        match self {
            IgvmPlatformHeader::SupportedPlatform(info) => {
                // Only one compatibility_mask value can be set.
                if info.compatibility_mask.count_ones() != 1 {
                    return Err(BinaryHeaderError::InvalidCompatibilityMask);
                }

                // Highest vtl must be 0 or 2.
                if info.highest_vtl != 0 && info.highest_vtl != 2 {
                    return Err(BinaryHeaderError::InvalidVtl);
                }

                // Platform type must be valid.
                match info.platform_type {
                    IgvmPlatformType::VSM_ISOLATION => {
                        if info.platform_version != IGVM_VSM_ISOLATION_PLATFORM_VERSION {
                            return Err(BinaryHeaderError::InvalidPlatformVersion);
                        }

                        if info.shared_gpa_boundary != 0 {
                            return Err(BinaryHeaderError::InvalidSharedGpaBoundary);
                        }
                    }
                    IgvmPlatformType::SEV_SNP => {
                        if info.platform_version != IGVM_SEV_SNP_PLATFORM_VERSION {
                            return Err(BinaryHeaderError::InvalidPlatformVersion);
                        }

                        // TODO: shared gpa boundary req?
                    }

                    IgvmPlatformType::TDX => {
                        if info.platform_version != IGVM_TDX_PLATFORM_VERSION {
                            return Err(BinaryHeaderError::InvalidPlatformVersion);
                        }
                        // TODO: shared gpa boundary req?
                    }

                    _ => {
                        return Err(BinaryHeaderError::InvalidPlatformType);
                    }
                }

                Ok(())
            }
        }
    }

    /// Create a new [`IgvmPlatformHeader`] from the binary slice provided.
    /// Returns the remaining slice of unused bytes.
    fn new_from_binary_split(
        mut variable_headers: &[u8],
    ) -> Result<(Self, &[u8]), BinaryHeaderError> {
        let header = read_header::<IGVM_VHS_VARIABLE_HEADER>(&mut variable_headers)?;

        if header.typ == IgvmVariableHeaderType::IGVM_VHT_SUPPORTED_PLATFORM
            && header.length == size_of::<IGVM_VHS_SUPPORTED_PLATFORM>() as u32
        {
            let header = IgvmPlatformHeader::SupportedPlatform(read_header(&mut variable_headers)?);
            header.validate()?;

            Ok((header, variable_headers))
        } else {
            Err(BinaryHeaderError::InvalidVariableHeaderType)
        }
    }

    /// Write the binary representation of the header and any associated file
    /// data to the supplied variable_headers and file data vectors.
    /// file_data_offset points to the start of the data section to be encoded
    /// in the variable header if this data has a file data component.
    #[cfg(feature = "igvm-c")]
    #[cfg_attr(docsrs, doc(cfg(feature = "igvm-c")))]
    fn write_binary_header(&self, variable_headers: &mut Vec<u8>) -> Result<(), BinaryHeaderError> {
        // Only serialize this header if valid.
        self.validate()?;

        match self {
            IgvmPlatformHeader::SupportedPlatform(platform) => {
                append_header(
                    platform,
                    IgvmVariableHeaderType::IGVM_VHT_SUPPORTED_PLATFORM,
                    variable_headers,
                );
            }
        }
        Ok(())
    }
}

/// Represents a structure in an IGVM variable header section, initialization
/// structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgvmInitializationHeader {
    GuestPolicy {
        policy: u64,
        compatibility_mask: u32,
    },
    RelocatableRegion {
        compatibility_mask: u32,
        relocation_alignment: u64,
        relocation_region_gpa: u64,
        relocation_region_size: u64,
        minimum_relocation_gpa: u64,
        maximum_relocation_gpa: u64,
        is_vtl2: bool,
        apply_rip_offset: bool,
        apply_gdtr_offset: bool,
        vp_index: u16,
        vtl: Vtl,
    },
    /// Represents an [IGVM_VHS_PAGE_TABLE_RELOCATION].
    PageTableRelocationRegion {
        compatibility_mask: u32,
        gpa: u64,
        size: u64,
        used_size: u64,
        vp_index: u16,
        vtl: Vtl,
    },
}

impl IgvmInitializationHeader {
    /// Get the in file variable header size of the given type.
    fn header_size(&self) -> usize {
        let additional = match self {
            IgvmInitializationHeader::GuestPolicy { .. } => size_of::<IGVM_VHS_GUEST_POLICY>(),
            IgvmInitializationHeader::RelocatableRegion { .. } => {
                size_of::<IGVM_VHS_RELOCATABLE_REGION>()
            }
            IgvmInitializationHeader::PageTableRelocationRegion { .. } => {
                size_of::<IGVM_VHS_PAGE_TABLE_RELOCATION>()
            }
        };

        size_of::<IGVM_VHS_VARIABLE_HEADER>() + additional
    }

    /// Get the [`IgvmVariableHeaderType`] for the initialization header.
    #[cfg(feature = "igvm-c")]
    #[cfg_attr(docsrs, doc(cfg(feature = "igvm-c")))]
    fn header_type(&self) -> IgvmVariableHeaderType {
        match self {
            IgvmInitializationHeader::GuestPolicy { .. } => {
                IgvmVariableHeaderType::IGVM_VHT_GUEST_POLICY
            }
            IgvmInitializationHeader::RelocatableRegion { .. } => {
                IgvmVariableHeaderType::IGVM_VHT_RELOCATABLE_REGION
            }
            IgvmInitializationHeader::PageTableRelocationRegion { .. } => {
                IgvmVariableHeaderType::IGVM_VHT_PAGE_TABLE_RELOCATION_REGION
            }
        }
    }

    /// Checks if this header contains valid state.
    fn validate(&self) -> Result<(), BinaryHeaderError> {
        match self {
            IgvmInitializationHeader::GuestPolicy {
                policy: _,
                compatibility_mask: _,
            } => {
                // TODO: check policy bits?
                Ok(())
            }
            IgvmInitializationHeader::RelocatableRegion {
                compatibility_mask: _,
                relocation_alignment,
                relocation_region_gpa,
                relocation_region_size,
                minimum_relocation_gpa,
                maximum_relocation_gpa,
                is_vtl2: _,
                apply_rip_offset: _,
                apply_gdtr_offset: _,
                vp_index: _,
                vtl: _,
            } => {
                if relocation_region_size % PAGE_SIZE_4K != 0 {
                    return Err(BinaryHeaderError::RelocationSize);
                }

                if relocation_alignment % PAGE_SIZE_4K != 0 {
                    return Err(BinaryHeaderError::RelocationAlignment);
                }

                if relocation_region_gpa % relocation_alignment != 0 {
                    return Err(BinaryHeaderError::RelocationAddress(*relocation_region_gpa));
                }

                if minimum_relocation_gpa % relocation_alignment != 0 {
                    return Err(BinaryHeaderError::RelocationAddress(
                        *minimum_relocation_gpa,
                    ));
                }

                if maximum_relocation_gpa % relocation_alignment != 0 {
                    return Err(BinaryHeaderError::RelocationAddress(
                        *maximum_relocation_gpa,
                    ));
                }

                Ok(())
            }
            IgvmInitializationHeader::PageTableRelocationRegion {
                compatibility_mask: _,
                gpa,
                size,
                used_size,
                vp_index: _,
                vtl: _,
            } => {
                if gpa % PAGE_SIZE_4K != 0 {
                    return Err(BinaryHeaderError::UnalignedAddress(*gpa));
                }

                if size % PAGE_SIZE_4K != 0 {
                    return Err(BinaryHeaderError::UnalignedSize(*size));
                }

                if used_size % PAGE_SIZE_4K != 0 {
                    return Err(BinaryHeaderError::UnalignedSize(*used_size));
                }

                if used_size > size {
                    return Err(BinaryHeaderError::InvalidPageTableRegionSize);
                }

                Ok(())
            }
        }
    }

    /// Create a new [`IgvmInitializationHeader`] from the binary slice provided.
    /// Returns the remaining slice of unused bytes.
    fn new_from_binary_split(
        mut variable_headers: &[u8],
    ) -> Result<(Self, &[u8]), BinaryHeaderError> {
        let IGVM_VHS_VARIABLE_HEADER { typ, length } =
            read_header::<IGVM_VHS_VARIABLE_HEADER>(&mut variable_headers)?;

        tracing::trace!(typ = ?typ, len = ?length, "trying to parse typ, len");

        let length = length as usize;

        let header = match typ {
            IgvmVariableHeaderType::IGVM_VHT_GUEST_POLICY
                if length == size_of::<IGVM_VHS_GUEST_POLICY>() =>
            {
                let IGVM_VHS_GUEST_POLICY {
                    policy,
                    compatibility_mask,
                    reserved,
                } = read_header(&mut variable_headers)?;

                if reserved != 0 {
                    return Err(BinaryHeaderError::ReservedNotZero);
                }

                IgvmInitializationHeader::GuestPolicy {
                    policy,
                    compatibility_mask,
                }
            }
            IgvmVariableHeaderType::IGVM_VHT_RELOCATABLE_REGION
                if length == size_of::<IGVM_VHS_RELOCATABLE_REGION>() =>
            {
                let IGVM_VHS_RELOCATABLE_REGION {
                    compatibility_mask,
                    flags,
                    relocation_alignment,
                    relocation_region_gpa,
                    relocation_region_size,
                    minimum_relocation_gpa,
                    maximum_relocation_gpa,
                    vp_index,
                    vtl,
                } = read_header(&mut variable_headers)?;

                let is_vtl2 = flags & IGVM_VHF_RELOCATABLE_REGION_IS_VTL2
                    == IGVM_VHF_RELOCATABLE_REGION_IS_VTL2;
                let apply_gdtr_offset = flags & IGVM_VHF_RELOCATABLE_REGION_APPLY_GDTR
                    == IGVM_VHF_RELOCATABLE_REGION_APPLY_GDTR;
                let apply_rip_offset = flags & IGVM_VHF_RELOCATABLE_REGION_APPLY_RIP
                    == IGVM_VHF_RELOCATABLE_REGION_APPLY_RIP;

                IgvmInitializationHeader::RelocatableRegion {
                    compatibility_mask,
                    relocation_alignment,
                    relocation_region_gpa,
                    relocation_region_size,
                    minimum_relocation_gpa,
                    maximum_relocation_gpa,
                    is_vtl2,
                    apply_gdtr_offset,
                    apply_rip_offset,
                    vp_index,
                    vtl: vtl.try_into().map_err(|_| BinaryHeaderError::InvalidVtl)?,
                }
            }
            IgvmVariableHeaderType::IGVM_VHT_PAGE_TABLE_RELOCATION_REGION
                if length == size_of::<IGVM_VHS_PAGE_TABLE_RELOCATION>() =>
            {
                let IGVM_VHS_PAGE_TABLE_RELOCATION {
                    gpa,
                    size,
                    used_size,
                    compatibility_mask,
                    reserved,
                    vp_index,
                    vtl,
                } = read_header(&mut variable_headers)?;

                if reserved != 0 {
                    return Err(BinaryHeaderError::ReservedNotZero);
                }

                IgvmInitializationHeader::PageTableRelocationRegion {
                    compatibility_mask,
                    gpa,
                    size,
                    used_size,
                    vp_index,
                    vtl: vtl.try_into().map_err(|_| BinaryHeaderError::InvalidVtl)?,
                }
            }

            _ => return Err(BinaryHeaderError::InvalidVariableHeaderType),
        };

        header.validate()?;
        Ok((header, variable_headers))
    }

    /// Returns the associated compatibility mask with the header, if any.
    fn compatibility_mask(&self) -> Option<u32> {
        use IgvmInitializationHeader::*;

        match self {
            GuestPolicy {
                compatibility_mask, ..
            } => Some(*compatibility_mask),
            RelocatableRegion {
                compatibility_mask, ..
            } => Some(*compatibility_mask),
            PageTableRelocationRegion {
                compatibility_mask, ..
            } => Some(*compatibility_mask),
        }
    }

    fn write_binary_header(&self, variable_headers: &mut Vec<u8>) -> Result<(), BinaryHeaderError> {
        // Only serialize this header if valid.
        self.validate()?;

        match self {
            IgvmInitializationHeader::GuestPolicy {
                policy,
                compatibility_mask,
            } => {
                let info = IGVM_VHS_GUEST_POLICY {
                    policy: *policy,
                    compatibility_mask: *compatibility_mask,
                    reserved: 0,
                };

                append_header(
                    &info,
                    IgvmVariableHeaderType::IGVM_VHT_GUEST_POLICY,
                    variable_headers,
                );
            }
            IgvmInitializationHeader::RelocatableRegion {
                compatibility_mask,
                relocation_alignment,
                relocation_region_gpa,
                relocation_region_size,
                minimum_relocation_gpa,
                maximum_relocation_gpa,
                is_vtl2,
                apply_rip_offset,
                apply_gdtr_offset,
                vp_index,
                vtl,
            } => {
                let mut flags = 0;

                if *is_vtl2 {
                    flags |= IGVM_VHF_RELOCATABLE_REGION_IS_VTL2;
                }

                if *apply_rip_offset {
                    flags |= IGVM_VHF_RELOCATABLE_REGION_APPLY_RIP;
                }

                if *apply_gdtr_offset {
                    flags |= IGVM_VHF_RELOCATABLE_REGION_APPLY_GDTR;
                }

                let info = IGVM_VHS_RELOCATABLE_REGION {
                    compatibility_mask: *compatibility_mask,
                    relocation_alignment: *relocation_alignment,
                    relocation_region_gpa: *relocation_region_gpa,
                    relocation_region_size: *relocation_region_size,
                    flags,
                    minimum_relocation_gpa: *minimum_relocation_gpa,
                    maximum_relocation_gpa: *maximum_relocation_gpa,
                    vp_index: *vp_index,
                    vtl: *vtl as u8,
                };

                append_header(
                    &info,
                    IgvmVariableHeaderType::IGVM_VHT_RELOCATABLE_REGION,
                    variable_headers,
                );
            }
            IgvmInitializationHeader::PageTableRelocationRegion {
                compatibility_mask,
                gpa,
                size,
                used_size,
                vp_index,
                vtl,
            } => {
                let info = IGVM_VHS_PAGE_TABLE_RELOCATION {
                    gpa: *gpa,
                    size: *size,
                    used_size: *used_size,
                    compatibility_mask: *compatibility_mask,
                    reserved: 0,
                    vp_index: *vp_index,
                    vtl: *vtl as u8,
                };

                append_header(
                    &info,
                    IgvmVariableHeaderType::IGVM_VHT_PAGE_TABLE_RELOCATION_REGION,
                    variable_headers,
                );
            }
        }

        Ok(())
    }
}

/// Represents a structure in an IGVM variable header section, directive
/// structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgvmDirectiveHeader {
    PageData {
        gpa: u64,
        compatibility_mask: u32,
        flags: IgvmPageDataFlags,
        data_type: IgvmPageDataType,
        data: Vec<u8>,
    },
    ParameterArea {
        number_of_bytes: u64,
        parameter_area_index: u32,
        initial_data: Vec<u8>,
    },
    VpCount(IGVM_VHS_PARAMETER),
    EnvironmentInfo(IGVM_VHS_PARAMETER),
    Srat(IGVM_VHS_PARAMETER),
    Madt(IGVM_VHS_PARAMETER),
    Slit(IGVM_VHS_PARAMETER),
    Pptt(IGVM_VHS_PARAMETER),
    MmioRanges(IGVM_VHS_PARAMETER),
    MemoryMap(IGVM_VHS_PARAMETER),
    CommandLine(IGVM_VHS_PARAMETER),
    DeviceTree(IGVM_VHS_PARAMETER),
    RequiredMemory {
        gpa: u64,
        compatibility_mask: u32,
        number_of_bytes: u32,
        vtl2_protectable: bool,
    },
    SnpVpContext {
        gpa: u64,
        compatibility_mask: u32,
        vp_index: u16,
        vmsa: Box<SevVmsa>,
    },
    /// Represents VP context for the BSP only.
    X64VbsVpContext {
        vtl: Vtl,
        registers: Vec<X86Register>,
        compatibility_mask: u32,
    },
    AArch64VbsVpContext {
        vtl: Vtl,
        registers: Vec<AArch64Register>,
        compatibility_mask: u32,
    },
    ParameterInsert(IGVM_VHS_PARAMETER_INSERT),
    ErrorRange {
        gpa: u64,
        compatibility_mask: u32,
        size_bytes: u32,
    },
    SnpIdBlock {
        compatibility_mask: u32,
        author_key_enabled: u8,
        reserved: [u8; 3],
        ld: [u8; 48],
        family_id: [u8; 16],
        image_id: [u8; 16],
        version: u32,
        guest_svn: u32,
        id_key_algorithm: u32,
        author_key_algorithm: u32,
        id_key_signature: Box<IGVM_VHS_SNP_ID_BLOCK_SIGNATURE>,
        id_public_key: Box<IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY>,
        author_key_signature: Box<IGVM_VHS_SNP_ID_BLOCK_SIGNATURE>,
        author_public_key: Box<IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY>,
    },
    VbsMeasurement {
        compatibility_mask: u32,
        version: u32,
        product_id: u32,
        module_id: u32,
        security_version: u32,
        policy_flags: u32,
        boot_digest_algo: u32,
        signing_algo: u32,
        boot_measurement_digest: Box<[u8; 64]>,
        signature: Box<[u8; 256]>,
        public_key: Box<[u8; 512]>,
    },
}

impl fmt::Display for IgvmDirectiveHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask,
                flags,
                data_type,
                data: _,
            } => {
                writeln!(f, "PageData {{")?;
                writeln!(f, "\t\tgpa: {:#X}", gpa)?;
                writeln!(f, "\t\tcompatibility_mask: {:#X}", compatibility_mask)?;
                writeln!(f, "\t\tflags: {:?}", flags)?;
                writeln!(f, "\t\tdata_type: {:?}", data_type)?;
                write!(f, "}}")?;
                Ok(())
            }
            IgvmDirectiveHeader::SnpIdBlock {
                compatibility_mask,
                author_key_enabled,
                reserved: _,
                ld,
                family_id,
                image_id,
                version,
                guest_svn,
                id_key_algorithm,
                author_key_algorithm,
                id_key_signature,
                id_public_key,
                author_key_signature,
                author_public_key,
            } => {
                writeln!(f, "IGVM_VHS_SNP_ID_BLOCK {{")?;
                writeln!(f, "\t\tcompatibility_mask: {:#X}", compatibility_mask)?;
                writeln!(f, "\t\tauthor_key_enabled: {:#X}", author_key_enabled)?;
                writeln!(f, "\t\tld: {}", hex::encode_upper(ld))?;
                writeln!(f, "\t\tfamily_id: {:#X}", family_id[0])?;
                writeln!(f, "\t\timage_id: {:#X}", image_id[0])?;
                writeln!(f, "\t\tversion: {:#X}", version)?;
                writeln!(f, "\t\tguest_svn: {:#X}", guest_svn)?;
                writeln!(f, "\t\tid_key_algorithm: {:#X}", id_key_algorithm)?;
                writeln!(f, "\t\tauthor_key_algorithm: {:#X}", author_key_algorithm)?;
                writeln!(
                    f,
                    "\t\tid_block_signature R: 0x{}",
                    hex::encode_upper(id_key_signature.r_comp)
                )?;
                writeln!(
                    f,
                    "\t\tid_block_signature S: 0x{}",
                    hex::encode_upper(id_key_signature.s_comp)
                )?;
                writeln!(
                    f,
                    "\t\tid_public_key qx: 0x{}",
                    hex::encode_upper(id_public_key.qx)
                )?;
                writeln!(
                    f,
                    "\t\tid_public_key qy: 0x{}",
                    hex::encode_upper(id_public_key.qy)
                )?;
                writeln!(f, "\t\tid_public_key curve: {:#X}", id_public_key.curve)?;
                if *author_key_enabled == 0x1 {
                    writeln!(
                        f,
                        "\t\tauthor_block_signature R: 0x{}",
                        hex::encode_upper(author_key_signature.r_comp)
                    )?;
                    writeln!(
                        f,
                        "\t\tauthor_block_signature S: 0x{}",
                        hex::encode_upper(author_key_signature.s_comp)
                    )?;
                    writeln!(
                        f,
                        "\t\tauthor_public_key qx: 0x{}",
                        hex::encode_upper(id_public_key.qx)
                    )?;
                    writeln!(
                        f,
                        "\t\tauthor_public_key qy: 0x{}",
                        hex::encode_upper(author_public_key.qy)
                    )?;
                    writeln!(
                        f,
                        "\t\tauthor_public_key curve: {:#X}",
                        author_public_key.curve
                    )?;
                }
                write!(f, "}}")?;
                Ok(())
            }
            IgvmDirectiveHeader::VbsMeasurement {
                compatibility_mask,
                version,
                product_id,
                module_id,
                security_version,
                policy_flags,
                boot_digest_algo,
                signing_algo,
                boot_measurement_digest,
                signature,
                public_key,
            } => {
                writeln!(f, "IGVM_VHS_VBS_MEASUREMENT {{")?;
                writeln!(f, "\tcompatibility_mask: {:#X}", compatibility_mask)?;
                writeln!(f, "\tversion: {:#X}", version)?;
                writeln!(f, "\tproduct_id: {:#X}", product_id)?;
                writeln!(f, "\tmodule_id: {:#X}", module_id)?;
                writeln!(f, "\tsecurity_version: {:#X}", security_version)?;
                writeln!(f, "\tpolicy_flags: {:#X}", policy_flags)?;
                writeln!(f, "\tboot_digest_algo: {:#X}", boot_digest_algo)?;
                writeln!(f, "\tsigning_algo: {:#X}", signing_algo)?;
                writeln!(
                    f,
                    "\tboot_measurement_digest: {}",
                    hex::encode_upper(boot_measurement_digest.as_ref())
                )?;
                writeln!(f, "\tsignature: {}", hex::encode_upper(signature.as_ref()))?;
                writeln!(
                    f,
                    "\tpublic_key: {}",
                    hex::encode_upper(public_key.as_ref())
                )?;
                write!(f, "}}")?;
                Ok(())
            }
            other => write!(f, "{:#X?}", other),
        }
    }
}

/// Binary serialization errors when converting a typed Rust
/// [`IgvmDirectiveHeader`] to the corresponding IGVM binary format or vice
/// versa.
#[derive(Debug, Error)]
pub enum BinaryHeaderError {
    #[error("address {0} is not aligned")]
    UnalignedAddress(u64),
    #[error("size {0} is not aligned")]
    UnalignedSize(u64),
    #[error("data is an invalid size")]
    InvalidDataSize,
    #[error("invalid variable header size")]
    InvalidVariableHeaderSize,
    #[error("invalid variable header type")]
    InvalidVariableHeaderType,
    #[error("invalid page data type")]
    InvalidPageDataType,
    #[error("invalid vp context platform type")]
    InvalidVpContextPlatformType,
    #[error("invalid vmsa")]
    InvalidVmsa,
    #[error("invalid compatibility mask")]
    InvalidCompatibilityMask,
    #[error("invalid vtl")]
    InvalidVtl,
    #[error("invalid platform type")]
    InvalidPlatformType,
    #[error("invalid platform version")]
    InvalidPlatformVersion,
    #[error("invalid shared gpa boundary")]
    InvalidSharedGpaBoundary,
    #[error("reserved values not zero")]
    ReservedNotZero,
    #[error("VBS vp context has no registers")]
    NoVbsVpContextRegisters,
    #[error("relocation region size not aligned to 4k")]
    RelocationSize,
    #[error("relocation alignment not aligned to 4k")]
    RelocationAlignment,
    #[error("relocation address not aligned to alignement")]
    RelocationAddress(u64),
    #[error("invalid page table entry size")]
    InvalidPageTableRegionSize,
    #[error("unsupported x64 register")]
    UnsupportedX64Register(#[from] registers::UnsupportedRegister<HvX64RegisterName>),
    #[error("unsupported AArch64 register")]
    UnsupportedAArch64Register(#[from] registers::UnsupportedRegister<HvArm64RegisterName>),
}

impl IgvmDirectiveHeader {
    /// Get the binary variable header size of the given type.
    fn header_size(&self) -> usize {
        let additional = match self {
            IgvmDirectiveHeader::PageData { .. } => size_of::<IGVM_VHS_PAGE_DATA>(),
            IgvmDirectiveHeader::ParameterArea { .. } => size_of::<IGVM_VHS_PARAMETER_AREA>(),
            IgvmDirectiveHeader::VpCount(param) => size_of_val(param),
            IgvmDirectiveHeader::EnvironmentInfo(param) => size_of_val(param),
            IgvmDirectiveHeader::Srat(param) => size_of_val(param),
            IgvmDirectiveHeader::Madt(param) => size_of_val(param),
            IgvmDirectiveHeader::Slit(param) => size_of_val(param),
            IgvmDirectiveHeader::Pptt(param) => size_of_val(param),
            IgvmDirectiveHeader::MmioRanges(param) => size_of_val(param),
            IgvmDirectiveHeader::MemoryMap(param) => size_of_val(param),
            IgvmDirectiveHeader::CommandLine(param) => size_of_val(param),
            IgvmDirectiveHeader::DeviceTree(param) => size_of_val(param),
            IgvmDirectiveHeader::RequiredMemory { .. } => size_of::<IGVM_VHS_REQUIRED_MEMORY>(),
            IgvmDirectiveHeader::SnpVpContext { .. } => size_of::<IGVM_VHS_VP_CONTEXT>(),
            IgvmDirectiveHeader::X64VbsVpContext { .. } => size_of::<IGVM_VHS_VP_CONTEXT>(),
            IgvmDirectiveHeader::AArch64VbsVpContext { .. } => size_of::<IGVM_VHS_VP_CONTEXT>(),
            IgvmDirectiveHeader::ParameterInsert(param) => size_of_val(param),
            IgvmDirectiveHeader::ErrorRange { .. } => size_of::<IGVM_VHS_ERROR_RANGE>(),
            IgvmDirectiveHeader::SnpIdBlock { .. } => size_of::<IGVM_VHS_SNP_ID_BLOCK>(),
            IgvmDirectiveHeader::VbsMeasurement { .. } => size_of::<IGVM_VHS_VBS_MEASUREMENT>(),
        };

        align_8(size_of::<IGVM_VHS_VARIABLE_HEADER>() + additional)
    }

    /// Get the [`IgvmVariableHeaderType`] for the directive header.
    #[cfg(feature = "igvm-c")]
    #[cfg_attr(docsrs, doc(cfg(feature = "igvm-c")))]
    fn header_type(&self) -> IgvmVariableHeaderType {
        match self {
            IgvmDirectiveHeader::PageData { .. } => IgvmVariableHeaderType::IGVM_VHT_PAGE_DATA,
            IgvmDirectiveHeader::ParameterArea { .. } => {
                IgvmVariableHeaderType::IGVM_VHT_PARAMETER_AREA
            }
            IgvmDirectiveHeader::VpCount(_) => IgvmVariableHeaderType::IGVM_VHT_VP_COUNT_PARAMETER,
            IgvmDirectiveHeader::Srat(_) => IgvmVariableHeaderType::IGVM_VHT_SRAT,
            IgvmDirectiveHeader::Madt(_) => IgvmVariableHeaderType::IGVM_VHT_MADT,
            IgvmDirectiveHeader::Slit(_) => IgvmVariableHeaderType::IGVM_VHT_SLIT,
            IgvmDirectiveHeader::Pptt(_) => IgvmVariableHeaderType::IGVM_VHT_PPTT,
            IgvmDirectiveHeader::MmioRanges(_) => IgvmVariableHeaderType::IGVM_VHT_MMIO_RANGES,
            IgvmDirectiveHeader::MemoryMap(_) => IgvmVariableHeaderType::IGVM_VHT_MEMORY_MAP,
            IgvmDirectiveHeader::CommandLine(_) => IgvmVariableHeaderType::IGVM_VHT_COMMAND_LINE,
            IgvmDirectiveHeader::DeviceTree(_) => IgvmVariableHeaderType::IGVM_VHT_DEVICE_TREE,
            IgvmDirectiveHeader::RequiredMemory { .. } => {
                IgvmVariableHeaderType::IGVM_VHT_REQUIRED_MEMORY
            }
            IgvmDirectiveHeader::SnpVpContext { .. } => IgvmVariableHeaderType::IGVM_VHT_VP_CONTEXT,
            IgvmDirectiveHeader::X64VbsVpContext { .. } => {
                IgvmVariableHeaderType::IGVM_VHT_VP_CONTEXT
            }
            IgvmDirectiveHeader::AArch64VbsVpContext { .. } => {
                IgvmVariableHeaderType::IGVM_VHT_VP_CONTEXT
            }
            IgvmDirectiveHeader::ParameterInsert(_) => {
                IgvmVariableHeaderType::IGVM_VHT_PARAMETER_INSERT
            }
            IgvmDirectiveHeader::ErrorRange { .. } => IgvmVariableHeaderType::IGVM_VHT_ERROR_RANGE,
            IgvmDirectiveHeader::SnpIdBlock { .. } => IgvmVariableHeaderType::IGVM_VHT_SNP_ID_BLOCK,
            IgvmDirectiveHeader::VbsMeasurement { .. } => {
                IgvmVariableHeaderType::IGVM_VHT_VBS_MEASUREMENT
            }
            IgvmDirectiveHeader::EnvironmentInfo(_) => {
                IgvmVariableHeaderType::IGVM_VHT_ENVIRONMENT_INFO_PARAMETER
            }
        }
    }

    /// Write the binary representation of the header and any associated file
    /// data to the supplied variable_headers and file data vectors.
    /// file_data_offset points to the start of the data section to be encoded
    /// in the variable header if this data has a file data component.
    pub fn write_binary_header(
        &self,
        file_data_offset: u32,
        variable_headers: &mut Vec<u8>,
        file_data: &mut Vec<u8>,
    ) -> Result<(), BinaryHeaderError> {
        // Only serialize this header if valid.
        self.validate()?;

        match self {
            IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask,
                flags,
                data_type,
                data,
            } => {
                let file_offset = if data.is_empty() {
                    // No data means a file offset of 0.
                    0
                } else {
                    // Pad data out to 4K if smaller. It must not be larger than
                    // 4K.
                    //
                    // TODO: Support 2MB page data
                    assert!(data.len() as u64 <= PAGE_SIZE_4K);

                    let align_up_iter =
                        std::iter::repeat(&0u8).take(PAGE_SIZE_4K as usize - data.len());
                    file_data.extend_from_slice(data);
                    file_data.extend(align_up_iter);

                    file_data_offset
                };

                let info = IGVM_VHS_PAGE_DATA {
                    gpa: *gpa,
                    compatibility_mask: *compatibility_mask,
                    file_offset,
                    flags: *flags,
                    data_type: *data_type,
                    reserved: 0,
                };

                append_header(
                    &info,
                    IgvmVariableHeaderType::IGVM_VHT_PAGE_DATA,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::ParameterArea {
                number_of_bytes,
                parameter_area_index,
                initial_data,
            } => {
                assert_eq!(number_of_bytes % PAGE_SIZE_4K, 0);

                let file_offset = if initial_data.is_empty() {
                    // No data means a file offset of 0.
                    0
                } else {
                    // Pad data out to number_of_bytes if smaller.
                    assert!(initial_data.len() as u64 <= *number_of_bytes);

                    let align_up_iter = std::iter::repeat(&0u8)
                        .take(*number_of_bytes as usize - initial_data.len());
                    file_data.extend_from_slice(initial_data);
                    file_data.extend(align_up_iter);

                    file_data_offset
                };

                let info = IGVM_VHS_PARAMETER_AREA {
                    number_of_bytes: *number_of_bytes,
                    parameter_area_index: *parameter_area_index,
                    file_offset,
                };

                append_header(
                    &info,
                    IgvmVariableHeaderType::IGVM_VHT_PARAMETER_AREA,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::VpCount(param) => {
                append_header(
                    param,
                    IgvmVariableHeaderType::IGVM_VHT_VP_COUNT_PARAMETER,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::EnvironmentInfo(param) => {
                append_header(
                    param,
                    IgvmVariableHeaderType::IGVM_VHT_ENVIRONMENT_INFO_PARAMETER,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::Srat(param) => {
                append_header(
                    param,
                    IgvmVariableHeaderType::IGVM_VHT_SRAT,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::Madt(param) => {
                append_header(
                    param,
                    IgvmVariableHeaderType::IGVM_VHT_MADT,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::Slit(param) => {
                append_header(
                    param,
                    IgvmVariableHeaderType::IGVM_VHT_SLIT,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::Pptt(param) => {
                append_header(
                    param,
                    IgvmVariableHeaderType::IGVM_VHT_PPTT,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::MmioRanges(param) => {
                append_header(
                    param,
                    IgvmVariableHeaderType::IGVM_VHT_MMIO_RANGES,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::MemoryMap(param) => {
                append_header(
                    param,
                    IgvmVariableHeaderType::IGVM_VHT_MEMORY_MAP,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::CommandLine(param) => {
                append_header(
                    param,
                    IgvmVariableHeaderType::IGVM_VHT_COMMAND_LINE,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::DeviceTree(param) => {
                append_header(
                    param,
                    IgvmVariableHeaderType::IGVM_VHT_DEVICE_TREE,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::RequiredMemory {
                gpa,
                compatibility_mask,
                number_of_bytes,
                vtl2_protectable,
            } => {
                // GPA and size must be 4k aligned.
                assert_eq!(gpa % PAGE_SIZE_4K, 0);
                assert_eq!(*number_of_bytes as u64 % PAGE_SIZE_4K, 0);

                let info = IGVM_VHS_REQUIRED_MEMORY {
                    gpa: *gpa,
                    compatibility_mask: *compatibility_mask,
                    number_of_bytes: *number_of_bytes,
                    flags: RequiredMemoryFlags::new().with_vtl2_protectable(*vtl2_protectable),
                    reserved: 0,
                };

                append_header(
                    &info,
                    IgvmVariableHeaderType::IGVM_VHT_REQUIRED_MEMORY,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::SnpVpContext {
                gpa,
                compatibility_mask,
                vp_index,
                vmsa,
            } => {
                // GPA must be 4k aligned.
                assert_eq!(gpa % PAGE_SIZE_4K, 0);

                // Pad file data to 4K.
                let align_up_iter =
                    std::iter::repeat(&0u8).take(PAGE_SIZE_4K as usize - vmsa.as_bytes().len());
                file_data.extend_from_slice(vmsa.as_bytes());
                file_data.extend(align_up_iter);

                let info = IGVM_VHS_VP_CONTEXT {
                    gpa: u64_le::new(*gpa),
                    compatibility_mask: *compatibility_mask,
                    file_offset: file_data_offset,
                    vp_index: *vp_index,
                    reserved: 0,
                };

                append_header(
                    &info,
                    IgvmVariableHeaderType::IGVM_VHT_VP_CONTEXT,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::X64VbsVpContext {
                vtl,
                registers,
                compatibility_mask,
            } => {
                let info = IGVM_VHS_VP_CONTEXT {
                    gpa: 0.into(),
                    compatibility_mask: *compatibility_mask,
                    file_offset: file_data_offset,
                    vp_index: 0,
                    reserved: 0,
                };

                // Build the serialized file data.
                let header = VbsVpContextHeader {
                    register_count: registers
                        .len()
                        .try_into()
                        .expect("reg count must fit in u32"),
                };
                file_data.extend_from_slice(header.as_bytes());

                for register in registers {
                    let vbs_reg = register.into_vbs_vp_context_reg(*vtl);
                    file_data.extend_from_slice(vbs_reg.as_bytes());
                }

                append_header(
                    &info,
                    IgvmVariableHeaderType::IGVM_VHT_VP_CONTEXT,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::AArch64VbsVpContext {
                vtl,
                registers,
                compatibility_mask,
            } => {
                let info = IGVM_VHS_VP_CONTEXT {
                    gpa: 0.into(),
                    compatibility_mask: *compatibility_mask,
                    file_offset: file_data_offset,
                    vp_index: 0,
                    reserved: 0,
                };

                // Build the serialized file data.
                let header = VbsVpContextHeader {
                    register_count: registers
                        .len()
                        .try_into()
                        .expect("reg count must fit in u32"),
                };
                file_data.extend_from_slice(header.as_bytes());

                for register in registers {
                    let vbs_reg = register.into_vbs_vp_context_reg(*vtl);
                    file_data.extend_from_slice(vbs_reg.as_bytes());
                }

                append_header(
                    &info,
                    IgvmVariableHeaderType::IGVM_VHT_VP_CONTEXT,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::ParameterInsert(param) => {
                // GPA must be 4k aligned.
                assert_eq!(param.gpa % PAGE_SIZE_4K, 0);

                append_header(
                    param,
                    IgvmVariableHeaderType::IGVM_VHT_PARAMETER_INSERT,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::ErrorRange { .. } => {
                todo!("append ErrorRange")
            }
            IgvmDirectiveHeader::SnpIdBlock {
                compatibility_mask,
                author_key_enabled,
                reserved,
                ld,
                family_id,
                image_id,
                version,
                guest_svn,
                id_key_algorithm,
                author_key_algorithm,
                id_key_signature,
                id_public_key,
                author_key_signature,
                author_public_key,
            } => {
                let id_block = IGVM_VHS_SNP_ID_BLOCK {
                    compatibility_mask: *compatibility_mask,
                    author_key_enabled: *author_key_enabled,
                    reserved: *reserved,
                    ld: *ld,
                    family_id: *family_id,
                    image_id: *image_id,
                    version: *version,
                    guest_svn: *guest_svn,
                    id_key_algorithm: *id_key_algorithm,
                    author_key_algorithm: *author_key_algorithm,
                    id_key_signature: **id_key_signature,
                    id_public_key: **id_public_key,
                    author_key_signature: **author_key_signature,
                    author_public_key: **author_public_key,
                };
                append_header(
                    &id_block,
                    IgvmVariableHeaderType::IGVM_VHT_SNP_ID_BLOCK,
                    variable_headers,
                );
            }
            IgvmDirectiveHeader::VbsMeasurement { .. } => {
                todo!("append VBS measurement")
            }
        }

        Ok(())
    }

    /// Returns the associated compatibility mask with the header, if any.
    pub fn compatibility_mask(&self) -> Option<u32> {
        use IgvmDirectiveHeader::*;

        match &self {
            PageData {
                compatibility_mask, ..
            } => Some(*compatibility_mask),
            ParameterArea { .. } => None,
            VpCount(_) => None,
            EnvironmentInfo(_) => None,
            Srat(_) => None,
            Madt(_) => None,
            Slit(_) => None,
            Pptt(_) => None,
            MmioRanges(_) => None,
            MemoryMap(_) => None,
            CommandLine(_) => None,
            DeviceTree(_) => None,
            RequiredMemory {
                compatibility_mask, ..
            } => Some(*compatibility_mask),
            SnpVpContext {
                compatibility_mask, ..
            } => Some(*compatibility_mask),
            X64VbsVpContext {
                compatibility_mask, ..
            } => Some(*compatibility_mask),
            AArch64VbsVpContext {
                compatibility_mask, ..
            } => Some(*compatibility_mask),
            ParameterInsert(info) => Some(info.compatibility_mask),
            ErrorRange {
                compatibility_mask, ..
            } => Some(*compatibility_mask),
            SnpIdBlock {
                compatibility_mask, ..
            } => Some(*compatibility_mask),
            VbsMeasurement {
                compatibility_mask, ..
            } => Some(*compatibility_mask),
        }
    }

    /// Returns a mutable reference to the associated compatibility mask with
    /// the header, if any.
    pub fn compatibility_mask_mut(&mut self) -> Option<&mut u32> {
        use IgvmDirectiveHeader::*;

        match self {
            PageData {
                compatibility_mask, ..
            } => Some(compatibility_mask),
            ParameterArea { .. } => None,
            VpCount(_) => None,
            EnvironmentInfo(_) => None,
            Srat(_) => None,
            Madt(_) => None,
            Slit(_) => None,
            Pptt(_) => None,
            MmioRanges(_) => None,
            MemoryMap(_) => None,
            CommandLine(_) => None,
            DeviceTree(_) => None,
            RequiredMemory {
                compatibility_mask, ..
            } => Some(compatibility_mask),
            SnpVpContext {
                compatibility_mask, ..
            } => Some(compatibility_mask),
            X64VbsVpContext {
                compatibility_mask, ..
            } => Some(compatibility_mask),
            AArch64VbsVpContext {
                compatibility_mask, ..
            } => Some(compatibility_mask),
            ParameterInsert(info) => Some(&mut info.compatibility_mask),
            ErrorRange {
                compatibility_mask, ..
            } => Some(compatibility_mask),
            SnpIdBlock {
                compatibility_mask, ..
            } => Some(compatibility_mask),
            VbsMeasurement {
                compatibility_mask, ..
            } => Some(compatibility_mask),
        }
    }

    /// Returns if `self` is equivalent to `other`, with equivalence being the
    /// headers match other than compatibility mask.
    pub fn equivalent(&self, other: &Self) -> bool {
        match (self, other) {
            (
                IgvmDirectiveHeader::PageData {
                    gpa: a_gpa,
                    flags: a_flags,
                    data_type: a_data_type,
                    data: a_data,
                    compatibility_mask: _,
                },
                IgvmDirectiveHeader::PageData {
                    gpa: b_gpa,
                    flags: b_flags,
                    data_type: b_data_type,
                    data: b_data,
                    compatibility_mask: _,
                },
            ) => {
                a_gpa == b_gpa
                    && a_flags == b_flags
                    && a_data_type == b_data_type
                    && a_data == b_data
            }
            (
                IgvmDirectiveHeader::RequiredMemory {
                    gpa: a_gpa,
                    number_of_bytes: a_number_of_bytes,
                    vtl2_protectable: a_vtl2_protectable,
                    compatibility_mask: _,
                },
                IgvmDirectiveHeader::RequiredMemory {
                    gpa: b_gpa,
                    number_of_bytes: b_number_of_bytes,
                    vtl2_protectable: b_vtl2_protectable,
                    compatibility_mask: _,
                },
            ) => {
                a_gpa == b_gpa
                    && a_number_of_bytes == b_number_of_bytes
                    && a_vtl2_protectable == b_vtl2_protectable
            }
            // TODO: other headers with compat masks
            _ => self == other,
        }
    }

    /// Checks if this header contains valid state.
    fn validate(&self) -> Result<(), BinaryHeaderError> {
        match self {
            IgvmDirectiveHeader::PageData {
                gpa,
                compatibility_mask: _,
                flags: _,
                data_type,
                data,
            } => {
                // TODO: support 2MB pages

                // GPA must be aligned.
                if gpa % PAGE_SIZE_4K != 0 {
                    return Err(BinaryHeaderError::UnalignedAddress(*gpa));
                }

                // Data type must be valid type.
                match *data_type {
                    IgvmPageDataType::NORMAL
                    | IgvmPageDataType::SECRETS
                    | IgvmPageDataType::CPUID_DATA
                    | IgvmPageDataType::CPUID_XF => {}
                    _ => return Err(BinaryHeaderError::InvalidPageDataType),
                }

                // Data must be less than 4K.
                if data.len() > PAGE_SIZE_4K as usize {
                    return Err(BinaryHeaderError::InvalidDataSize);
                }
            }
            IgvmDirectiveHeader::ParameterArea {
                number_of_bytes,
                parameter_area_index: _,
                initial_data,
            } => {
                if number_of_bytes % PAGE_SIZE_4K != 0 {
                    return Err(BinaryHeaderError::UnalignedSize(*number_of_bytes));
                }

                if initial_data.len() > *number_of_bytes as usize {
                    return Err(BinaryHeaderError::InvalidDataSize);
                }
            }
            // Parameter usage is validated by the IgvmFile functions, as more
            // info is needed than just this header.
            IgvmDirectiveHeader::VpCount(_)
            | IgvmDirectiveHeader::EnvironmentInfo(_)
            | IgvmDirectiveHeader::Srat(_)
            | IgvmDirectiveHeader::Madt(_)
            | IgvmDirectiveHeader::Slit(_)
            | IgvmDirectiveHeader::Pptt(_)
            | IgvmDirectiveHeader::MmioRanges(_)
            | IgvmDirectiveHeader::MemoryMap(_)
            | IgvmDirectiveHeader::CommandLine(_)
            | IgvmDirectiveHeader::DeviceTree(_) => {}
            IgvmDirectiveHeader::RequiredMemory {
                gpa,
                compatibility_mask: _,
                number_of_bytes,
                vtl2_protectable: _,
            } => {
                if gpa % PAGE_SIZE_4K != 0 {
                    return Err(BinaryHeaderError::UnalignedAddress(*gpa));
                }

                if *number_of_bytes as u64 % PAGE_SIZE_4K != 0 {
                    return Err(BinaryHeaderError::UnalignedSize(*number_of_bytes as u64));
                }
            }
            IgvmDirectiveHeader::SnpVpContext {
                gpa,
                compatibility_mask: _,
                vp_index: _,
                vmsa: _,
            } => {
                if gpa % PAGE_SIZE_4K != 0 {
                    return Err(BinaryHeaderError::UnalignedAddress(*gpa));
                }
            }
            IgvmDirectiveHeader::X64VbsVpContext {
                vtl: _,
                registers: _,
                compatibility_mask: _,
            } => {}
            IgvmDirectiveHeader::AArch64VbsVpContext {
                vtl: _,
                registers: _,
                compatibility_mask: _,
            } => {}
            IgvmDirectiveHeader::ParameterInsert(param) => {
                if param.gpa % PAGE_SIZE_4K != 0 {
                    return Err(BinaryHeaderError::UnalignedAddress(param.gpa));
                }
            }
            IgvmDirectiveHeader::ErrorRange { gpa, .. } => {
                // GPA must be aligned.
                if gpa % PAGE_SIZE_4K != 0 {
                    return Err(BinaryHeaderError::UnalignedAddress(*gpa));
                }
            }
            //TODO: validate SNP
            IgvmDirectiveHeader::SnpIdBlock { .. } => {}
            //TODO: validate VBS
            IgvmDirectiveHeader::VbsMeasurement { .. } => {}
        }

        Ok(())
    }

    /// Create a new [`IgvmDirectiveHeader`] from a binary representation, with
    /// the following slices representing the variable headers and file data
    /// sections of the IGVM file.
    ///
    /// Returns the remaining variable_headers slice after this header is
    /// constructed.
    fn new_from_binary_split<'a>(
        revision: IgvmRevision,
        mut variable_headers: &'a [u8],
        file_data: &'a [u8],
        file_data_start: u32,
        compatibility_mask_to_platforms: impl Fn(u32) -> Option<IgvmPlatformType>,
    ) -> Result<(Self, &'a [u8]), BinaryHeaderError> {
        // First read the fixed header.
        let IGVM_VHS_VARIABLE_HEADER { typ, length } = read_header(&mut variable_headers)?;

        tracing::trace!(typ = ?typ, len = ?length, "trying to parse typ, len");

        let length = length as usize;
        // Extract file data from a given file offest with the given size. File
        // offset of 0 results in no data.
        let extract_file_data =
            |file_offset: u32, size: usize| -> Result<Vec<u8>, BinaryHeaderError> {
                if file_offset == 0 {
                    return Ok(Vec::new());
                }

                let start = (file_offset - file_data_start) as usize;
                let end = start + size;

                file_data
                    .get(start..end)
                    .ok_or(BinaryHeaderError::InvalidDataSize)
                    .map(|slice| slice.to_vec())
            };
        let header = match typ {
            IgvmVariableHeaderType::IGVM_VHT_PARAMETER_AREA
                if length == size_of::<IGVM_VHS_PARAMETER_AREA>() =>
            {
                let IGVM_VHS_PARAMETER_AREA {
                    file_offset,
                    number_of_bytes,
                    parameter_area_index,
                } = read_header(&mut variable_headers)?;

                let data = extract_file_data(file_offset, number_of_bytes as usize)?;

                IgvmDirectiveHeader::ParameterArea {
                    number_of_bytes,
                    parameter_area_index,
                    initial_data: data,
                }
            }
            IgvmVariableHeaderType::IGVM_VHT_PAGE_DATA
                if length == size_of::<IGVM_VHS_PAGE_DATA>() =>
            {
                let IGVM_VHS_PAGE_DATA {
                    gpa,
                    compatibility_mask,
                    flags,
                    data_type,
                    file_offset,
                    reserved,
                } = read_header(&mut variable_headers)?;

                // TODO: only 4K data supported
                let data = extract_file_data(file_offset, PAGE_SIZE_4K as usize)?;

                if reserved != 0 {
                    return Err(BinaryHeaderError::ReservedNotZero);
                }

                IgvmDirectiveHeader::PageData {
                    gpa,
                    compatibility_mask,
                    flags,
                    data_type,
                    data,
                }
            }
            IgvmVariableHeaderType::IGVM_VHT_PARAMETER_INSERT
                if length == size_of::<IGVM_VHS_PARAMETER_INSERT>() =>
            {
                IgvmDirectiveHeader::ParameterInsert(read_header(&mut variable_headers)?)
            }
            IgvmVariableHeaderType::IGVM_VHT_VP_CONTEXT
                if length == size_of::<IGVM_VHS_VP_CONTEXT>() =>
            {
                // Clone the reference here as we manually advance the slice by
                // the aligned size, not the size of the structure.
                let header = read_header::<IGVM_VHS_VP_CONTEXT>(&mut &*variable_headers)?;

                // Advance variable_headers by aligned up size
                let aligned_size = align_8(size_of::<IGVM_VHS_VP_CONTEXT>());
                variable_headers = variable_headers
                    .get(aligned_size..)
                    .ok_or(BinaryHeaderError::InvalidVariableHeaderSize)?;

                match compatibility_mask_to_platforms(header.compatibility_mask) {
                    Some(IgvmPlatformType::VSM_ISOLATION) => {
                        // First read the VbsVpContextHeader at file offset
                        let start = (header.file_offset - file_data_start) as usize;
                        let (VbsVpContextHeader { register_count }, remaining_data) =
                            VbsVpContextHeader::read_from_prefix_split(&file_data[start..])
                                .ok_or(BinaryHeaderError::InvalidDataSize)?;

                        let mut registers: Vec<VbsVpContextRegister> = Vec::new();
                        let mut vp_vtl: Option<u8> = None;
                        let mut remaining_data = remaining_data;

                        for _ in 0..register_count {
                            let reg = match VbsVpContextRegister::read_from_prefix_split(
                                remaining_data,
                            ) {
                                Some((reg, slice)) => {
                                    remaining_data = slice;
                                    reg
                                }
                                None => return Err(BinaryHeaderError::InvalidDataSize),
                            };

                            registers.push(reg);

                            // TODO: single vtl expected
                            match vp_vtl {
                                Some(vtl) => assert_eq!(vtl, reg.vtl),
                                None => vp_vtl = Some(reg.vtl),
                            }
                        }

                        // TODO: only bsp supported
                        let vp_index = header.vp_index;
                        assert_eq!(vp_index, 0);

                        let vtl = vp_vtl
                            .ok_or(BinaryHeaderError::NoVbsVpContextRegisters)?
                            .try_into()
                            .map_err(|_| BinaryHeaderError::InvalidVtl)?;

                        match revision.arch() {
                            Arch::X64 => {
                                let registers: Result<Vec<X86Register>, _> = registers
                                    .iter()
                                    .map(|reg| X86Register::try_from(*reg))
                                    .collect();

                                IgvmDirectiveHeader::X64VbsVpContext {
                                    vtl,
                                    registers: registers?,
                                    compatibility_mask: header.compatibility_mask,
                                }
                            }
                            Arch::AArch64 => {
                                let registers: Result<Vec<AArch64Register>, _> = registers
                                    .iter()
                                    .map(|reg| AArch64Register::try_from(*reg))
                                    .collect();

                                IgvmDirectiveHeader::AArch64VbsVpContext {
                                    vtl,
                                    registers: registers?,
                                    compatibility_mask: header.compatibility_mask,
                                }
                            }
                        }
                    }
                    Some(IgvmPlatformType::SEV_SNP) => {
                        // Read the VMSA which is stored as 4K file data.
                        let start = (header.file_offset - file_data_start) as usize;
                        if file_data.len() < start {
                            return Err(BinaryHeaderError::InvalidDataSize);
                        }

                        let data = file_data
                            .get(start..)
                            .and_then(|x| x.get(..PAGE_SIZE_4K as usize))
                            .ok_or(BinaryHeaderError::InvalidDataSize)?;

                        // Copy the VMSA bytes into the VMSA, and validate the remaining bytes are 0.
                        let mut vmsa = SevVmsa::new_box_zeroed();
                        let (vmsa_slice, remaining) = data.split_at(size_of::<SevVmsa>());
                        vmsa.as_bytes_mut().copy_from_slice(vmsa_slice);
                        if remaining.iter().any(|b| *b != 0) {
                            return Err(BinaryHeaderError::InvalidVmsa);
                        }

                        IgvmDirectiveHeader::SnpVpContext {
                            gpa: header.gpa.into(),
                            compatibility_mask: header.compatibility_mask,
                            vp_index: header.vp_index,
                            vmsa,
                        }
                    }
                    _ => {
                        // Unsupported compatibility mask or isolation type
                        return Err(BinaryHeaderError::InvalidVpContextPlatformType);
                    }
                }
            }
            IgvmVariableHeaderType::IGVM_VHT_REQUIRED_MEMORY
                if length == size_of::<IGVM_VHS_REQUIRED_MEMORY>() =>
            {
                let IGVM_VHS_REQUIRED_MEMORY {
                    gpa,
                    compatibility_mask,
                    number_of_bytes,
                    flags,
                    reserved,
                } = read_header(&mut variable_headers)?;

                if reserved != 0 {
                    return Err(BinaryHeaderError::ReservedNotZero);
                }

                let vtl2_protectable = flags.vtl2_protectable();

                IgvmDirectiveHeader::RequiredMemory {
                    gpa,
                    compatibility_mask,
                    number_of_bytes,
                    vtl2_protectable,
                }
            }
            IgvmVariableHeaderType::IGVM_VHT_VP_COUNT_PARAMETER
                if length == size_of::<IGVM_VHS_PARAMETER>() =>
            {
                IgvmDirectiveHeader::VpCount(read_header(&mut variable_headers)?)
            }
            IgvmVariableHeaderType::IGVM_VHT_ENVIRONMENT_INFO_PARAMETER
                if length == size_of::<IGVM_VHS_PARAMETER>() =>
            {
                IgvmDirectiveHeader::EnvironmentInfo(read_header(&mut variable_headers)?)
            }
            IgvmVariableHeaderType::IGVM_VHT_SRAT if length == size_of::<IGVM_VHS_PARAMETER>() => {
                IgvmDirectiveHeader::Srat(read_header(&mut variable_headers)?)
            }
            IgvmVariableHeaderType::IGVM_VHT_MADT if length == size_of::<IGVM_VHS_PARAMETER>() => {
                IgvmDirectiveHeader::Madt(read_header(&mut variable_headers)?)
            }
            IgvmVariableHeaderType::IGVM_VHT_SLIT if length == size_of::<IGVM_VHS_PARAMETER>() => {
                IgvmDirectiveHeader::Slit(read_header(&mut variable_headers)?)
            }
            IgvmVariableHeaderType::IGVM_VHT_PPTT if length == size_of::<IGVM_VHS_PARAMETER>() => {
                IgvmDirectiveHeader::Pptt(read_header(&mut variable_headers)?)
            }
            IgvmVariableHeaderType::IGVM_VHT_MMIO_RANGES
                if length == size_of::<IGVM_VHS_PARAMETER>() =>
            {
                IgvmDirectiveHeader::MmioRanges(read_header(&mut variable_headers)?)
            }
            IgvmVariableHeaderType::IGVM_VHT_SNP_ID_BLOCK
                if length == size_of::<IGVM_VHS_SNP_ID_BLOCK>() =>
            {
                let IGVM_VHS_SNP_ID_BLOCK {
                    compatibility_mask,
                    author_key_enabled,
                    reserved,
                    ld,
                    family_id,
                    image_id,
                    version,
                    guest_svn,
                    id_key_algorithm,
                    author_key_algorithm,
                    id_key_signature,
                    id_public_key,
                    author_key_signature,
                    author_public_key,
                } = read_header(&mut variable_headers)?;
                IgvmDirectiveHeader::SnpIdBlock {
                    compatibility_mask,
                    author_key_enabled,
                    reserved,
                    ld,
                    family_id,
                    image_id,
                    version,
                    guest_svn,
                    id_key_algorithm,
                    author_key_algorithm,
                    id_key_signature: Box::new(id_key_signature),
                    id_public_key: Box::new(id_public_key),
                    author_key_signature: Box::new(author_key_signature),
                    author_public_key: Box::new(author_public_key),
                }
            }
            IgvmVariableHeaderType::IGVM_VHT_VBS_MEASUREMENT
                if length == size_of::<IGVM_VHS_VBS_MEASUREMENT>() =>
            {
                let IGVM_VHS_VBS_MEASUREMENT {
                    compatibility_mask,
                    version,
                    product_id,
                    module_id,
                    security_version,
                    policy_flags,
                    boot_digest_algo,
                    signing_algo,
                    boot_measurement_digest,
                    signature,
                    public_key,
                } = read_header(&mut variable_headers)?;
                IgvmDirectiveHeader::VbsMeasurement {
                    compatibility_mask,
                    version,
                    product_id,
                    module_id,
                    security_version,
                    policy_flags,
                    boot_digest_algo,
                    signing_algo,
                    boot_measurement_digest: Box::new(boot_measurement_digest),
                    signature: Box::new(signature),
                    public_key: Box::new(public_key),
                }
            }
            IgvmVariableHeaderType::IGVM_VHT_MEMORY_MAP
                if length == size_of::<IGVM_VHS_PARAMETER>() =>
            {
                IgvmDirectiveHeader::MemoryMap(read_header(&mut variable_headers)?)
            }
            IgvmVariableHeaderType::IGVM_VHT_ERROR_RANGE
                if length == size_of::<IGVM_VHS_ERROR_RANGE>() =>
            {
                let IGVM_VHS_ERROR_RANGE {
                    gpa,
                    compatibility_mask,
                    size_bytes,
                } = read_header(&mut variable_headers)?;
                IgvmDirectiveHeader::ErrorRange {
                    gpa,
                    compatibility_mask,
                    size_bytes,
                }
            }
            IgvmVariableHeaderType::IGVM_VHT_COMMAND_LINE
                if length == size_of::<IGVM_VHS_PARAMETER>() =>
            {
                IgvmDirectiveHeader::CommandLine(read_header(&mut variable_headers)?)
            }
            IgvmVariableHeaderType::IGVM_VHT_DEVICE_TREE
                if length == size_of::<IGVM_VHS_PARAMETER>() =>
            {
                IgvmDirectiveHeader::DeviceTree(read_header(&mut variable_headers)?)
            }
            _ => return Err(BinaryHeaderError::InvalidVariableHeaderType),
        };

        header.validate()?;
        Ok((header, variable_headers))
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("no valid platform headers")]
    NoPlatformHeaders,
    #[error("file data section too large")]
    FileDataSectionTooLarge,
    #[error("variable header section too large")]
    VariableHeaderSectionTooLarge,
    #[error("total file size too large")]
    TotalFileSizeTooLarge,
    #[error("invalid binary platform header")]
    InvalidBinaryPlatformHeader(#[source] BinaryHeaderError),
    #[error("invalid binary initialization header")]
    InvalidBinaryInitializationHeader(#[source] BinaryHeaderError),
    #[error("invalid binary directive header")]
    InvalidBinaryDirectiveHeader(#[source] BinaryHeaderError),
    #[error("multiple platform headers with the same isolation type")]
    MultiplePlatformHeadersWithSameIsolation,
    #[error("invalid parameter area index")]
    InvalidParameterAreaIndex,
    #[error("invalid platform type")]
    InvalidPlatformType,
    #[error("no free compatibility masks")]
    NoFreeCompatibilityMasks,
    #[error("invalid fixed header")]
    InvalidFixedHeader,
    #[error("invalid binary variable header section")]
    InvalidBinaryVariableHeaderSection,
    #[error("invalid checksum in fixed header, expected {expected} was {header_value}")]
    InvalidChecksum { expected: u32, header_value: u32 },
    #[error("page table relocation header specified twice for a compatibiltiy mask")]
    MultiplePageTableRelocationHeaders,
    #[error("relocation regions overlap")]
    RelocationRegionsOverlap,
    #[error("parameter insert inside page table region")]
    ParameterInsertInsidePageTableRegion,
    #[error("no matching vp context for vp index and vtl")]
    NoMatchingVpContext,
    #[error("platform {platform:?} not supported on architecture {arch:?}")]
    PlatformArchUnsupported {
        arch: Arch,
        platform: igvm_defs::IgvmPlatformType,
    },
    #[error("invalid header type {header_type} on arch {arch:?}")]
    InvalidHeaderArch { arch: Arch, header_type: String },
    #[error("page size of 0x{0:x} unsupported")]
    UnsupportedPageSize(u32),
    #[error("invalid fixed header arch")]
    InvalidFixedHeaderArch(u32),
    #[error("merged igvm files are not the same revision")]
    MergeRevision,
}

/// Architecture for an IGVM file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X64,
    AArch64,
}

impl From<Arch> for IgvmArchitecture {
    fn from(value: Arch) -> Self {
        match value {
            Arch::X64 => IgvmArchitecture::X64,
            Arch::AArch64 => IgvmArchitecture::AARCH64,
        }
    }
}

/// Format revision for an IGVM file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgvmRevision {
    V1,
    V2 {
        /// Architecture for the IGVM file.
        arch: Arch,
        /// Page size for the IGVM file.
        page_size: u32,
    },
}

impl IgvmRevision {
    fn arch(&self) -> Arch {
        match self {
            IgvmRevision::V1 => Arch::X64,
            IgvmRevision::V2 { arch, .. } => *arch,
        }
    }

    fn page_size(&self) -> u64 {
        match self {
            IgvmRevision::V1 => PAGE_SIZE_4K,
            IgvmRevision::V2 { page_size, .. } => *page_size as u64,
        }
    }

    fn fixed_header_size(&self) -> usize {
        match self {
            IgvmRevision::V1 => size_of::<IGVM_FIXED_HEADER>(),
            IgvmRevision::V2 { .. } => size_of::<IGVM_FIXED_HEADER_V2>(),
        }
    }
}

/// An in-memory IGVM file that can be used to load a guest, or serialized to
/// the binary format.
#[derive(Debug, Clone)]
pub struct IgvmFile {
    revision: IgvmRevision,
    platform_headers: Vec<IgvmPlatformHeader>,
    initialization_headers: Vec<IgvmInitializationHeader>,
    directive_headers: Vec<IgvmDirectiveHeader>,
}

impl fmt::Display for IgvmFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{:#X?}", self.platform_headers)?;
        writeln!(f, "{:#X?}", self.initialization_headers)?;
        for h in &self.directive_headers {
            writeln!(f, "{}", h)?;
        }
        Ok(())
    }
}

/// Represents information about an IGVM relocatable region.
#[derive(Debug, Clone)]
pub struct IgvmRelocatableRegion {
    pub base_gpa: u64,
    pub size: u64,
    pub relocation_alignment: u64,
    pub minimum_relocation_gpa: u64,
    pub maximum_relocation_gpa: u64,
    pub is_vtl2: bool,
    pub apply_rip_offset: bool,
    pub apply_gdtr_offset: bool,
    pub vp_index: u16,
    pub vtl: Vtl,
}

impl IgvmRelocatableRegion {
    /// Check if a gpa is contained within this relocatable region.
    pub fn contains(&self, gpa: u64) -> bool {
        let end = self.base_gpa + self.size;
        gpa >= self.base_gpa && gpa < end
    }

    /// Check if a relocation_base gpa is valid or not.
    pub fn relocation_base_valid(&self, relocation_base: u64) -> bool {
        // New base must be aligned, and start and end must live within the
        // acceptable relocation range.
        let start = relocation_base;
        let end = relocation_base + self.size;

        if start % self.relocation_alignment != 0 {
            tracing::debug!("base is not aligned");
            false
        } else if start < self.minimum_relocation_gpa {
            tracing::debug!("base is too low");
            false
        } else if end > self.maximum_relocation_gpa {
            tracing::debug!("end is too high");
            false
        } else {
            true
        }
    }
}

#[derive(Debug, Clone)]
struct VpIdentifier {
    compatibility_mask: u32,
    vp_index: u16,
    vtl: Vtl,
}

#[derive(Debug, Clone)]
struct PageTableRegion {
    compatibility_mask: u32,
    gpa: u64,
    size: u64,
}

#[derive(Debug, Clone)]
struct DirectiveHeaderValidationInfo {
    used_vp_idents: Vec<VpIdentifier>,
    page_table_regions: Vec<PageTableRegion>,
}

fn extract_individual_masks(mut compatibility_mask: u32) -> Vec<u32> {
    let mut masks = Vec::new();
    while compatibility_mask != 0 {
        let single_mask = 1 << compatibility_mask.trailing_zeros();
        masks.push(single_mask);
        compatibility_mask &= !single_mask;
    }
    masks
}

/// Represents an IGVM fixed header.
#[derive(Debug, Clone)]
enum FixedHeader {
    V1(IGVM_FIXED_HEADER),
    V2(IGVM_FIXED_HEADER_V2),
}

impl FixedHeader {
    /// Get the fixed header as raw bytes.
    fn as_bytes(&self) -> &[u8] {
        match self {
            FixedHeader::V1(raw) => raw.as_bytes(),
            FixedHeader::V2(raw) => raw.as_bytes(),
        }
    }

    fn set_total_file_size(&mut self, size: u32) {
        match self {
            FixedHeader::V1(raw) => raw.total_file_size = size,
            FixedHeader::V2(raw) => raw.total_file_size = size,
        }
    }

    fn set_checksum(&mut self, checksum: u32) {
        match self {
            FixedHeader::V1(raw) => raw.checksum = checksum,
            FixedHeader::V2(raw) => raw.checksum = checksum,
        }
    }

    fn magic(&self) -> u32 {
        match self {
            FixedHeader::V1(raw) => raw.magic,
            FixedHeader::V2(raw) => raw.magic,
        }
    }

    fn format_version(&self) -> u32 {
        match self {
            FixedHeader::V1(raw) => raw.format_version,
            FixedHeader::V2(raw) => raw.format_version,
        }
    }

    fn total_file_size(&self) -> u32 {
        match self {
            FixedHeader::V1(raw) => raw.total_file_size,
            FixedHeader::V2(raw) => raw.total_file_size,
        }
    }

    fn variable_header_offset(&self) -> u32 {
        match self {
            FixedHeader::V1(raw) => raw.variable_header_offset,
            FixedHeader::V2(raw) => raw.variable_header_offset,
        }
    }

    fn variable_header_size(&self) -> u32 {
        match self {
            FixedHeader::V1(raw) => raw.variable_header_size,
            FixedHeader::V2(raw) => raw.variable_header_size,
        }
    }

    fn checksum(&self) -> u32 {
        match self {
            FixedHeader::V1(raw) => raw.checksum,
            FixedHeader::V2(raw) => raw.checksum,
        }
    }
}

impl IgvmFile {
    /// Check if the given platform headers are valid.
    ///
    /// Validates that:
    /// - There is at least 1 platform header
    /// - Each isolation type is valid
    /// - Each isolation type is only used once
    /// - Isolation type is consistent with arch
    fn validate_platform_headers<'a>(
        revision: IgvmRevision,
        platform_headers: impl Iterator<Item = &'a IgvmPlatformHeader>,
    ) -> Result<(), Error> {
        let mut at_least_one = false;
        let mut isolation_types = HashMap::new();

        for header in platform_headers {
            at_least_one = true;
            header
                .validate()
                .map_err(Error::InvalidBinaryPlatformHeader)?;

            match header {
                IgvmPlatformHeader::SupportedPlatform(info) => {
                    match info.platform_type {
                        IgvmPlatformType::VSM_ISOLATION => {}
                        IgvmPlatformType::SEV_SNP | IgvmPlatformType::TDX => {
                            if revision.arch() != Arch::X64 {
                                return Err(Error::PlatformArchUnsupported {
                                    arch: revision.arch(),
                                    platform: info.platform_type,
                                });
                            }
                        }
                        _ => return Err(Error::InvalidPlatformType),
                    }

                    if let Some(prev) = isolation_types.insert(info.platform_type, info) {
                        tracing::trace!(
                            current = ?info,
                            prev = ?prev,
                            "current platform header conflicts with previous duplicate header"
                        );
                        return Err(Error::MultiplePlatformHeadersWithSameIsolation);
                    }
                }
            }
        }

        if !at_least_one {
            Err(Error::NoPlatformHeaders)
        } else {
            Ok(())
        }
    }

    /// Check if the given initialization headers are valid.
    ///
    /// Returns additional info used to validate directive headers.
    fn validate_initialization_headers(
        revision: IgvmRevision,
        initialization_headers: &[IgvmInitializationHeader],
    ) -> Result<DirectiveHeaderValidationInfo, Error> {
        let mut page_table_masks = 0;
        let mut used_vp_idents: Vec<VpIdentifier> = Vec::new();
        let mut reloc_regions: HashMap<u32, RangeMap<u64, ()>> = HashMap::new();
        let mut page_table_regions = Vec::new();

        let mut check_region_overlap =
            |compatibility_mask: u32, start: u64, size: u64| -> Result<(), Error> {
                for mask in extract_individual_masks(compatibility_mask) {
                    let regions = match reloc_regions.get_mut(&mask) {
                        Some(value) => value,
                        None => {
                            reloc_regions.insert(mask, RangeMap::new());
                            reloc_regions.get_mut(&mask).expect("just inserted")
                        }
                    };

                    if !regions.insert(start..=start + size - 1, ()) {
                        return Err(Error::RelocationRegionsOverlap);
                    }
                }

                Ok(())
            };

        for header in initialization_headers {
            // Each individual header needs to be valid.
            header
                .validate()
                .map_err(Error::InvalidBinaryInitializationHeader)?;

            // Do the following additional validation:
            //  - A page table relocation header may only be specified once per
            //    compatability mask.
            //  - Relocation regions and page table regions for a given
            //    compatibility mask may not overlap.
            //  - Keep track of which page table regions, vp_index, and vtls for
            //    use in validating directive headers.
            match header {
                IgvmInitializationHeader::PageTableRelocationRegion {
                    compatibility_mask,
                    gpa,
                    size,
                    used_size: _,
                    vp_index,
                    vtl,
                } => {
                    if revision.arch() != Arch::X64 {
                        return Err(Error::InvalidHeaderArch {
                            arch: revision.arch(),
                            header_type: "PageTableRelocationRegion".into(),
                        });
                    }

                    // Header can be only specified once per compatibility mask
                    if compatibility_mask & page_table_masks != 0 {
                        return Err(Error::MultiplePageTableRelocationHeaders);
                    }
                    page_table_masks |= compatibility_mask;

                    check_region_overlap(*compatibility_mask, *gpa, *size)?;

                    used_vp_idents.push(VpIdentifier {
                        compatibility_mask: *compatibility_mask,
                        vp_index: *vp_index,
                        vtl: *vtl,
                    });
                    page_table_regions.push(PageTableRegion {
                        compatibility_mask: *compatibility_mask,
                        gpa: *gpa,
                        size: *size,
                    })
                }
                IgvmInitializationHeader::RelocatableRegion {
                    compatibility_mask,
                    relocation_alignment: _,
                    relocation_region_gpa,
                    relocation_region_size,
                    minimum_relocation_gpa: _,
                    maximum_relocation_gpa: _,
                    is_vtl2: _,
                    apply_rip_offset: _,
                    apply_gdtr_offset: _,
                    vp_index,
                    vtl,
                } => {
                    if revision.arch() != Arch::X64 {
                        return Err(Error::InvalidHeaderArch {
                            arch: revision.arch(),
                            header_type: "RelocatableRegion".into(),
                        });
                    }

                    check_region_overlap(
                        *compatibility_mask,
                        *relocation_region_gpa,
                        *relocation_region_size,
                    )?;

                    used_vp_idents.push(VpIdentifier {
                        compatibility_mask: *compatibility_mask,
                        vp_index: *vp_index,
                        vtl: *vtl,
                    })
                }
                // TODO: validate SNP policy compatibility mask specifies SNP
                _ => {}
            }
        }

        Ok(DirectiveHeaderValidationInfo {
            used_vp_idents,
            page_table_regions,
        })
    }

    /// Check if the given directive headers are valid.
    ///
    /// Validates that:
    ///  - Parameter indicies are declared first in a parameter area
    ///  - Parameter indicies are not declared more than once
    ///
    /// TODO: compatability masks? vp contexts match isolation arch? individual
    /// header alignment?
    fn validate_directive_headers(
        revision: IgvmRevision,
        directive_headers: &[IgvmDirectiveHeader],
        mut validation_info: DirectiveHeaderValidationInfo,
    ) -> Result<(), Error> {
        #[derive(PartialEq, Eq)]
        enum ParameterAreaState {
            Allocated,
            Inserted,
        }
        let mut parameter_areas: BTreeMap<u32, ParameterAreaState> = BTreeMap::new();

        // TODO: validate parameter usage offset falls within parameter area size

        for header in directive_headers {
            header
                .validate()
                .map_err(Error::InvalidBinaryDirectiveHeader)?;

            match header {
                IgvmDirectiveHeader::PageData { .. } => {}
                IgvmDirectiveHeader::ParameterArea {
                    parameter_area_index,
                    ..
                } => {
                    // This must be the first use of this parameter index
                    if parameter_areas
                        .insert(*parameter_area_index, ParameterAreaState::Allocated)
                        .is_some()
                    {
                        return Err(Error::InvalidParameterAreaIndex);
                    }
                }
                IgvmDirectiveHeader::VpCount(info)
                | IgvmDirectiveHeader::EnvironmentInfo(info)
                | IgvmDirectiveHeader::Srat(info)
                | IgvmDirectiveHeader::Madt(info)
                | IgvmDirectiveHeader::Slit(info)
                | IgvmDirectiveHeader::Pptt(info)
                | IgvmDirectiveHeader::MmioRanges(info)
                | IgvmDirectiveHeader::MemoryMap(info)
                | IgvmDirectiveHeader::CommandLine(info)
                | IgvmDirectiveHeader::DeviceTree(info) => {
                    match parameter_areas.get(&info.parameter_area_index) {
                        Some(ParameterAreaState::Allocated) => {}
                        _ => return Err(Error::InvalidParameterAreaIndex),
                    }
                }
                IgvmDirectiveHeader::RequiredMemory { .. } => {}
                IgvmDirectiveHeader::SnpVpContext { .. } => {
                    // TODO: Validate vp info for SNP. Need max enabled VTL for given platform as that's the
                    //       which VTL this vmsa refers to.
                }
                IgvmDirectiveHeader::X64VbsVpContext {
                    vtl,
                    registers: _,
                    compatibility_mask,
                } => {
                    if revision.arch() != Arch::X64 {
                        return Err(Error::InvalidHeaderArch {
                            arch: revision.arch(),
                            header_type: "X64VbsVpContext".into(),
                        });
                    }

                    // Remove all vp identifiers that refer to this vp context. The vp_index is 0.
                    validation_info.used_vp_idents.retain(|ident| {
                        !((ident.compatibility_mask & compatibility_mask != 0)
                            && ident.vp_index == 0
                            && ident.vtl == *vtl)
                    })
                }
                IgvmDirectiveHeader::AArch64VbsVpContext {
                    vtl,
                    registers: _,
                    compatibility_mask,
                } => {
                    if revision.arch() != Arch::AArch64 {
                        return Err(Error::InvalidHeaderArch {
                            arch: revision.arch(),
                            header_type: "AArch64VbsVpContext".into(),
                        });
                    }

                    // Remove all vp identifiers that refer to this vp context. The vp_index is 0.
                    validation_info.used_vp_idents.retain(|ident| {
                        !((ident.compatibility_mask & compatibility_mask != 0)
                            && ident.vp_index == 0
                            && ident.vtl == *vtl)
                    })
                }
                IgvmDirectiveHeader::ParameterInsert(info) => {
                    match parameter_areas.get_mut(&info.parameter_area_index) {
                        Some(state) if *state == ParameterAreaState::Allocated => {
                            // Parameter index can no longer be used again.
                            *state = ParameterAreaState::Inserted;
                        }
                        _ => return Err(Error::InvalidParameterAreaIndex),
                    }

                    // Cannot insert within a page table region
                    if validation_info.page_table_regions.iter().any(|region| {
                        let start = region.gpa;
                        let end = region.gpa + region.size;
                        (region.compatibility_mask & info.compatibility_mask != 0)
                            && info.gpa >= start
                            && info.gpa < end
                    }) {
                        return Err(Error::ParameterInsertInsidePageTableRegion);
                    }
                }
                IgvmDirectiveHeader::ErrorRange { .. } => {} // TODO: Validate ErrorRange
                IgvmDirectiveHeader::SnpIdBlock { .. } => {} // TODO: Validate Snp
                IgvmDirectiveHeader::VbsMeasurement { .. } => {} // TODO: Validate Vbs
            }
        }

        if !validation_info.used_vp_idents.is_empty() {
            return Err(Error::NoMatchingVpContext);
        }

        Ok(())
    }

    /// Serialize this IGVM file into the binary format, into the supplied
    /// output Vec.
    pub fn serialize(&self, output: &mut Vec<u8>) -> Result<(), Error> {
        IgvmFile::validate_platform_headers(self.revision, self.platform_headers.iter())?;

        // Build the variable header and file data section by looping through each header type.
        // First, calculate the starting data file offset relative to the rest of the file.
        let mut variable_header_section_size = 0;
        for header in self.platform_headers.iter() {
            variable_header_section_size += header.header_size();
        }
        for header in self.initialization_headers.iter() {
            variable_header_section_size += header.header_size();
        }
        for header in self.directive_headers.iter() {
            variable_header_section_size += header.header_size();
        }

        // TODO: All headers should be 8 byte aligned. Const assert and downgrade this to a debug_assert instead?
        assert_eq!(variable_header_section_size % 8, 0);

        // The file data section starts after the fixed header and variable header section.
        let file_data_section_start =
            self.revision.fixed_header_size() + variable_header_section_size;

        let mut variable_header_binary = Vec::new();
        let mut file_data = Vec::new();

        // Add platform headers
        for header in &self.platform_headers {
            match header {
                IgvmPlatformHeader::SupportedPlatform(platform) => {
                    let header = IGVM_VHS_VARIABLE_HEADER {
                        typ: IgvmVariableHeaderType::IGVM_VHT_SUPPORTED_PLATFORM,
                        length: platform.as_bytes().len() as u32,
                    };
                    variable_header_binary.extend_from_slice(header.as_bytes());
                    variable_header_binary.extend_from_slice(platform.as_bytes());
                }
            }
        }

        // Add initialization headers
        for header in &self.initialization_headers {
            header
                .write_binary_header(&mut variable_header_binary)
                .map_err(Error::InvalidBinaryDirectiveHeader)?;
            assert_eq!(variable_header_binary.len() % 8, 0);
        }

        // Add directive headers
        for header in &self.directive_headers {
            header
                .write_binary_header(
                    (file_data_section_start + file_data.len())
                        .try_into()
                        .map_err(|_| Error::FileDataSectionTooLarge)?,
                    &mut variable_header_binary,
                    &mut file_data,
                )
                .map_err(Error::InvalidBinaryDirectiveHeader)?;
            // TODO: All structure definitions should be 8 byte aligned. Should const assert defs instead and
            //       downgrade this or leave this assert in?
            assert_eq!(variable_header_binary.len() % 8, 0);
        }

        assert_eq!(variable_header_section_size, variable_header_binary.len());

        let mut fixed_header = match self.revision {
            IgvmRevision::V1 => FixedHeader::V1(IGVM_FIXED_HEADER {
                magic: IGVM_MAGIC_VALUE,
                format_version: IGVM_FORMAT_VERSION_1,
                variable_header_offset: size_of::<IGVM_FIXED_HEADER>() as u32,
                variable_header_size: variable_header_binary
                    .len()
                    .try_into()
                    .map_err(|_| Error::VariableHeaderSectionTooLarge)?,
                total_file_size: 0,
                checksum: 0,
            }),
            IgvmRevision::V2 { arch, page_size } => FixedHeader::V2(IGVM_FIXED_HEADER_V2 {
                magic: IGVM_MAGIC_VALUE,
                format_version: IGVM_FORMAT_VERSION_2,
                variable_header_offset: size_of::<IGVM_FIXED_HEADER_V2>() as u32,
                variable_header_size: variable_header_binary
                    .len()
                    .try_into()
                    .map_err(|_| Error::VariableHeaderSectionTooLarge)?,
                total_file_size: 0,
                checksum: 0,
                architecture: arch.into(),
                page_size,
            }),
        };

        // Create the fixed header
        let total_file_size =
            fixed_header.as_bytes().len() + variable_header_binary.len() + file_data.len();

        fixed_header.set_total_file_size(
            total_file_size
                .try_into()
                .map_err(|_| Error::TotalFileSizeTooLarge)?,
        );

        // Calculate the checksum which consists of a CRC32 of just the fixed and variable headers.
        // It does not include the file data.
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(fixed_header.as_bytes());
        hasher.update(&variable_header_binary);
        let checksum = hasher.finalize();
        fixed_header.set_checksum(checksum);

        // Flatten into a single vector representing the whole file
        output.extend_from_slice(fixed_header.as_bytes());
        output.append(&mut variable_header_binary);
        output.append(&mut file_data);

        Ok(())
    }

    /// Create a new [`IgvmFile`] from the given headers.
    pub fn new(
        revision: IgvmRevision,
        platform_headers: Vec<IgvmPlatformHeader>,
        initialization_headers: Vec<IgvmInitializationHeader>,
        directive_headers: Vec<IgvmDirectiveHeader>,
    ) -> Result<Self, Error> {
        // TODO: support non 4K page sizes.
        if revision.page_size() != PAGE_SIZE_4K {
            return Err(Error::UnsupportedPageSize(revision.page_size() as u32));
        }

        Self::validate_platform_headers(revision, platform_headers.iter())?;
        let validation_info =
            Self::validate_initialization_headers(revision, &initialization_headers)?;
        Self::validate_directive_headers(revision, &directive_headers, validation_info)?;

        Ok(Self {
            revision,
            platform_headers,
            initialization_headers,
            directive_headers,
        })
    }

    /// Create a new [`IgvmFile`] from a serialized binary representation. An
    /// optional filter can be specified to filter headers that do not apply to
    /// the given isolation platform.
    pub fn new_from_binary(
        file: &[u8],
        isolation_filter: Option<IsolationType>,
    ) -> Result<Self, Error> {
        let total_size = file.len();

        // Read the IGVM fixed header
        let mut fixed_header = FixedHeader::V1(
            IGVM_FIXED_HEADER::read_from_prefix(file).ok_or(Error::InvalidFixedHeader)?,
        );

        if fixed_header.magic() != IGVM_MAGIC_VALUE {
            return Err(Error::InvalidFixedHeader);
        }

        let revision = match fixed_header.format_version() {
            IGVM_FORMAT_VERSION_1 => IgvmRevision::V1,
            IGVM_FORMAT_VERSION_2 => {
                let v2 = IGVM_FIXED_HEADER_V2::read_from_prefix(file)
                    .ok_or(Error::InvalidFixedHeader)?;

                let arch = match v2.architecture {
                    IgvmArchitecture::X64 => Arch::X64,
                    IgvmArchitecture::AARCH64 => Arch::AArch64,
                    _ => return Err(Error::InvalidFixedHeader),
                };

                if v2.page_size != PAGE_SIZE_4K as u32 {
                    return Err(Error::UnsupportedPageSize(v2.page_size));
                }

                let revision = IgvmRevision::V2 {
                    arch,
                    page_size: v2.page_size,
                };

                fixed_header = FixedHeader::V2(v2);
                revision
            }
            _ => return Err(Error::InvalidFixedHeader),
        };

        if fixed_header.total_file_size() as usize != total_size {
            return Err(Error::InvalidFixedHeader);
        }

        let variable_header_start = fixed_header.variable_header_offset() as usize;

        if variable_header_start >= total_size {
            return Err(Error::InvalidFixedHeader);
        }

        let file_data_start =
            fixed_header.variable_header_offset() + fixed_header.variable_header_size();

        if file_data_start as usize >= total_size {
            return Err(Error::InvalidFixedHeader);
        }

        // Split file into variable headers and file data
        let (mut variable_headers, file_data) =
            file[variable_header_start..].split_at(fixed_header.variable_header_size() as usize);

        // Validate the checksum. The checksum is calculated with the
        // fixed_header and variable header section, with the fixed header
        // checksum field set to zero.
        let mut fixed_header_calculate_checksum = fixed_header.clone();
        fixed_header_calculate_checksum.set_checksum(0);
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(fixed_header_calculate_checksum.as_bytes());
        hasher.update(variable_headers);
        let checksum = hasher.finalize();

        if fixed_header.checksum() != checksum {
            return Err(Error::InvalidChecksum {
                expected: checksum,
                header_value: fixed_header.checksum(),
            });
        }

        #[derive(PartialEq, Eq)]
        enum VariableHeaderParsingStage {
            Platform,
            Initialization,
            Directive,
        }

        let mut parsing_stage = VariableHeaderParsingStage::Platform;
        let mut platform_headers = Vec::new();
        let mut initialization_headers = Vec::new();
        let mut directive_headers = Vec::new();
        let mut filter_mask: u32 = 0xFFFFFFFF;
        let isolation_filter: Option<IgvmPlatformType> = isolation_filter.map(|typ| typ.into());
        let mut mask_map: HashMap<u32, IgvmPlatformType> = HashMap::new();

        while !variable_headers.is_empty() {
            // Peek the next fixed variable header to determine what kind of header to parse
            match IGVM_VHS_VARIABLE_HEADER::read_from_prefix(variable_headers) {
                Some(header) if IGVM_VHT_RANGE_PLATFORM.contains(&header.typ.0) => {
                    if parsing_stage != VariableHeaderParsingStage::Platform {
                        // Only legal to parse platform headers before other types
                        return Err(Error::InvalidBinaryVariableHeaderSection);
                    }

                    let (header, new_slice) =
                        IgvmPlatformHeader::new_from_binary_split(variable_headers)
                            .map_err(Error::InvalidBinaryPlatformHeader)?;

                    match header {
                        IgvmPlatformHeader::SupportedPlatform(info) => {
                            // Setup filter_mask based on isolation_filter
                            if let Some(filter_type) = isolation_filter {
                                if filter_type == info.platform_type {
                                    filter_mask = info.compatibility_mask;
                                }
                            }

                            mask_map.insert(info.compatibility_mask, info.platform_type);
                        }
                    }

                    platform_headers.push(header);
                    variable_headers = new_slice;
                }
                Some(header) if IGVM_VHT_RANGE_INIT.contains(&header.typ.0) => {
                    match parsing_stage {
                        VariableHeaderParsingStage::Platform => {
                            parsing_stage = VariableHeaderParsingStage::Initialization
                        }
                        VariableHeaderParsingStage::Initialization => {}
                        VariableHeaderParsingStage::Directive => {
                            return Err(Error::InvalidBinaryVariableHeaderSection);
                        }
                    }

                    let (header, new_slice) =
                        IgvmInitializationHeader::new_from_binary_split(variable_headers)
                            .map_err(Error::InvalidBinaryInitializationHeader)?;

                    variable_headers = new_slice;

                    if let Some(mask) = header.compatibility_mask() {
                        if mask & filter_mask == 0 {
                            // Skip this header, does not apply to the isolation filter
                            continue;
                        }
                    }

                    initialization_headers.push(header);
                }
                Some(header) if IGVM_VHT_RANGE_DIRECTIVE.contains(&header.typ.0) => {
                    match parsing_stage {
                        VariableHeaderParsingStage::Platform
                        | VariableHeaderParsingStage::Initialization => {
                            parsing_stage = VariableHeaderParsingStage::Directive
                        }
                        VariableHeaderParsingStage::Directive => {}
                    }

                    let compatibility_mask_to_platforms =
                        |mask: u32| -> Option<IgvmPlatformType> { mask_map.get(&mask).copied() };

                    let (header, new_slice) = IgvmDirectiveHeader::new_from_binary_split(
                        revision,
                        variable_headers,
                        file_data,
                        file_data_start,
                        compatibility_mask_to_platforms,
                    )
                    .map_err(Error::InvalidBinaryDirectiveHeader)?;

                    variable_headers = new_slice;

                    if let Some(mask) = header.compatibility_mask() {
                        if mask & filter_mask == 0 {
                            // Skip this header, does not apply to the isolation filter
                            continue;
                        }
                    }

                    directive_headers.push(header);
                }
                other => {
                    eprintln!("invalid header: {:?}", Some(other));
                    return Err(Error::InvalidBinaryVariableHeaderSection);
                }
            }
        }

        IgvmFile::new(
            revision,
            platform_headers,
            initialization_headers,
            directive_headers,
        )
    }

    /// Get the platform headers in this file.
    pub fn platforms(&self) -> &[IgvmPlatformHeader] {
        self.platform_headers.as_slice()
    }

    /// Get the initialization headers in this file.
    pub fn initializations(&self) -> &[IgvmInitializationHeader] {
        self.initialization_headers.as_slice()
    }

    /// Get the directive headers in this file.
    pub fn directives(&self) -> &[IgvmDirectiveHeader] {
        self.directive_headers.as_slice()
    }

    /// Get the relocation regions and page table builder in this file for a
    /// given compatibility mask. If relocation is not supported, None is
    /// returned.
    pub fn relocations(
        &self,
        compatibility_mask: u32,
    ) -> (
        Option<Vec<IgvmRelocatableRegion>>,
        Option<PageTableRelocationBuilder>,
    ) {
        let mut regions = Vec::new();
        let mut page_table_fixup = None;

        for header in &self.initialization_headers {
            if let Some(mask) = header.compatibility_mask() {
                if mask & compatibility_mask != compatibility_mask {
                    continue;
                }
            }

            match header {
                IgvmInitializationHeader::RelocatableRegion {
                    compatibility_mask: _,
                    relocation_alignment,
                    relocation_region_gpa,
                    relocation_region_size,
                    minimum_relocation_gpa,
                    maximum_relocation_gpa,
                    is_vtl2,
                    apply_rip_offset,
                    apply_gdtr_offset,
                    vp_index,
                    vtl,
                } => {
                    regions.push(IgvmRelocatableRegion {
                        base_gpa: *relocation_region_gpa,
                        relocation_alignment: *relocation_alignment,
                        size: *relocation_region_size,
                        minimum_relocation_gpa: *minimum_relocation_gpa,
                        maximum_relocation_gpa: *maximum_relocation_gpa,
                        is_vtl2: *is_vtl2,
                        apply_rip_offset: *apply_rip_offset,
                        apply_gdtr_offset: *apply_gdtr_offset,
                        vp_index: *vp_index,
                        vtl: *vtl,
                    });
                }
                IgvmInitializationHeader::PageTableRelocationRegion {
                    compatibility_mask: _,
                    gpa,
                    size,
                    used_size,
                    vp_index,
                    vtl,
                } => {
                    assert!(page_table_fixup.is_none());
                    page_table_fixup = Some(PageTableRelocationBuilder::new(
                        *gpa, *size, *used_size, *vp_index, *vtl,
                    ))
                }
                _ => {}
            }
        }

        let regions = if !regions.is_empty() {
            Some(regions)
        } else {
            None
        };
        (regions, page_table_fixup)
    }

    /// Merge the `other` [`IgvmFile`] into `self`.
    ///
    /// This will change compatabilty masks of `other` if any conflict with the
    /// current file.
    ///
    /// Parameter area indices will be changed to avoid any conflicts. While
    /// it's technically possible to merge parameter areas, it would require
    /// each parameter usage within that parameter area match exactly between
    /// different platforms due to only the final parameter insert having a
    /// compatibility mask.
    ///
    /// To preserve all potential measurements in both `self` and `other`,
    /// merging is stable and will not modify the relative order of directives
    /// in both IGVM files.
    pub fn merge(&mut self, mut other: IgvmFile) -> Result<(), Error> {
        // Individual validation on each IgvmFile should have already been done.
        // Validate the combination of both is valid.
        #[cfg(debug_assertions)]
        {
            debug_assert!(Self::validate_platform_headers(
                self.revision,
                self.platform_headers.iter()
            )
            .is_ok());
            debug_assert!(Self::validate_platform_headers(
                other.revision,
                other.platform_headers.iter()
            )
            .is_ok());
            let self_info =
                Self::validate_initialization_headers(self.revision, &self.initialization_headers)
                    .expect("valid file");
            let other_info = Self::validate_initialization_headers(
                other.revision,
                &other.initialization_headers,
            )
            .expect("valid file");
            debug_assert!(Self::validate_directive_headers(
                self.revision,
                &self.directive_headers,
                self_info
            )
            .is_ok());
            debug_assert!(Self::validate_directive_headers(
                other.revision,
                &other.directive_headers,
                other_info
            )
            .is_ok());
        }

        if self.revision != other.revision {
            return Err(Error::MergeRevision);
        }

        Self::validate_platform_headers(
            self.revision,
            self.platform_headers
                .iter()
                .chain(other.platform_headers.iter()),
        )?;

        // Check the platform headers for each file to see if they need to be
        // fixed up or not. Do this by first checking which masks are used in
        // `self`, and then creating a fixup map for `other`.
        let mut used_compatibility_masks =
            self.platform_headers
                .iter()
                .fold(0, |mask, header| match header {
                    IgvmPlatformHeader::SupportedPlatform(platform) => {
                        mask | platform.compatibility_mask
                    }
                });
        let mut fixup_masks_map = HashMap::new();
        for header in &other.platform_headers {
            match header {
                IgvmPlatformHeader::SupportedPlatform(platform) => {
                    if platform.compatibility_mask & used_compatibility_masks != 0 {
                        // Find the next free compatibility mask
                        let free_bit = used_compatibility_masks.trailing_ones();

                        if free_bit > 32 {
                            // This can never be reached, as there aren't 32
                            // different isolation architectures and the earlier
                            // validation of platform headers should have
                            // failed. But return an error anyways if this case
                            // is ever reached.
                            return Err(Error::NoFreeCompatibilityMasks);
                        }

                        let new_mask = 1u32 << free_bit;
                        used_compatibility_masks |= new_mask;

                        assert!(fixup_masks_map
                            .insert(platform.compatibility_mask, new_mask)
                            .is_none());
                    }
                }
            }
        }

        let fixup_masks_map = fixup_masks_map;
        let fixup_mask_all_bits = fixup_masks_map.iter().fold(0, |mask, entry| mask | entry.0);

        let fixup_mask = |mask: &mut u32| {
            let mut bits_to_be_fixed: u32 = *mask & fixup_mask_all_bits;
            while bits_to_be_fixed != 0 {
                let old_mask = 1 << bits_to_be_fixed.trailing_zeros();
                let new_mask = fixup_masks_map
                    .get(&old_mask)
                    .expect("old_mask should always be present");
                *mask = (!old_mask & *mask) | new_mask;
                bits_to_be_fixed &= !old_mask;
            }
        };

        // Fixup parameter area indices by first seeing which ones are used in
        // `self`.
        let mut used_parameter_indices = BTreeSet::new();
        let mut fixup_parameter_index_map: BTreeMap<u32, u32> = BTreeMap::new();
        for header in &self.directive_headers {
            use IgvmDirectiveHeader::*;
            if let ParameterArea {
                parameter_area_index,
                ..
            } = header
            {
                // Self should never use a parameter area twice, as the IgvmFile
                // should always be valid.
                assert!(
                    used_parameter_indices.insert(*parameter_area_index),
                    "invalid igvm file, parameter index used twice"
                );
            }
        }

        // NOTE: This could be optimized by using some sort of interval tree and
        //       merging consecutive usages into adjacent ranges, then iterating
        //       through ranges to find the first available gap. However, the
        //       current loaders do not use that many parameter areas, so linear
        //       search shouldn't be very slow as the map is small.
        let allocate_new_parameter_index =
            |used_parameter_indices: &mut BTreeSet<u32>| -> Result<u32, Error> {
                // new index must fit into a u32
                let mut new_index: u32 = used_parameter_indices
                    .len()
                    .try_into()
                    .map_err(|_| Error::InvalidParameterAreaIndex)?;
                for (index, val) in used_parameter_indices.iter().enumerate() {
                    let index = index as u32;
                    if index != *val {
                        new_index = index;
                        break;
                    }
                }
                assert!(used_parameter_indices.insert(new_index));
                Ok(new_index)
            };

        let fixup_parameter_index =
            |index: &mut u32, fixup_parameter_index_map: &BTreeMap<u32, u32>| {
                // A None entry means that this paramter index does not need to
                // be fixed up
                if let Some(new_index) = fixup_parameter_index_map.get(index) {
                    *index = *new_index;
                }
            };

        // Fixup all compatibility masks in platform and init headers.
        for header in &mut other.platform_headers {
            match header {
                IgvmPlatformHeader::SupportedPlatform(platform) => {
                    fixup_mask(&mut platform.compatibility_mask)
                }
            }
        }

        for header in &mut other.initialization_headers {
            match header {
                IgvmInitializationHeader::GuestPolicy {
                    policy: _,
                    compatibility_mask,
                } => fixup_mask(compatibility_mask),
                IgvmInitializationHeader::RelocatableRegion {
                    compatibility_mask, ..
                } => fixup_mask(compatibility_mask),
                IgvmInitializationHeader::PageTableRelocationRegion {
                    compatibility_mask, ..
                } => fixup_mask(compatibility_mask),
            }
        }

        // Fixup all compatibility masks and parameter area index usage in
        // directive headers.
        for header in &mut other.directive_headers {
            use IgvmDirectiveHeader::*;

            if let Some(mask) = header.compatibility_mask_mut() {
                fixup_mask(mask);
            }

            match header {
                RequiredMemory { .. }
                | PageData { .. }
                | SnpVpContext { .. }
                | ErrorRange { .. }
                | SnpIdBlock { .. }
                | VbsMeasurement { .. }
                | X64VbsVpContext { .. }
                | AArch64VbsVpContext { .. } => {}
                ParameterArea {
                    parameter_area_index,
                    ..
                } => {
                    if used_parameter_indices.contains(parameter_area_index) {
                        // If the parameter area conflicts with ones in self,
                        // replace it according to the map. An existing fixup
                        // entry means this index was used twice, and `other` is
                        // invalid.
                        match fixup_parameter_index_map.get(parameter_area_index) {
                            Some(_) => panic!("igvm file is invalid, parameter index used twice"),
                            None => {
                                let new_index =
                                    allocate_new_parameter_index(&mut used_parameter_indices)?;
                                assert!(fixup_parameter_index_map
                                    .insert(*parameter_area_index, new_index)
                                    .is_none());
                                *parameter_area_index = new_index;
                            }
                        }
                    }
                }
                VpCount(info)
                | EnvironmentInfo(info)
                | Srat(info)
                | Madt(info)
                | Slit(info)
                | Pptt(info)
                | MmioRanges(info)
                | MemoryMap(info)
                | CommandLine(info)
                | DeviceTree(info) => {
                    fixup_parameter_index(
                        &mut info.parameter_area_index,
                        &fixup_parameter_index_map,
                    );
                }
                ParameterInsert(insert) => {
                    fixup_parameter_index(
                        &mut insert.parameter_area_index,
                        &fixup_parameter_index_map,
                    );
                }
            }
        }

        // Non-directive headers are just appeneded to the current file.
        self.platform_headers.append(&mut other.platform_headers);
        self.initialization_headers
            .append(&mut other.initialization_headers);

        // Merge or append each directive header, searching starting from the
        // back.
        let mut insert_index = 0;
        'outer: for other_header in other.directive_headers {
            // Limit the search space to the earliest possible insertion point
            // that would not break relative ordering.
            for (index, header) in self.directive_headers[insert_index..]
                .iter_mut()
                .enumerate()
                .rev()
            {
                if header.equivalent(&other_header) {
                    match (
                        header.compatibility_mask_mut(),
                        other_header.compatibility_mask(),
                    ) {
                        (Some(header_mask), Some(other_header_mask)) => {
                            debug_assert!(*header_mask & other_header_mask == 0);
                            *header_mask |= other_header_mask
                        }
                        (None, None) => {}
                        _ => unreachable!(),
                    }
                    // Search now ends after this merged header. Since we
                    // limited the slice earlier, we add the index + 1 to the
                    // overall starting point.
                    insert_index += index + 1;
                    continue 'outer;
                }
            }
            // Unable to merge the header into an existing header, append at the
            // specified index and update the end of search index.
            self.directive_headers.insert(insert_index, other_header);
            insert_index += 1;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hv_defs::HvArm64RegisterName;
    use crate::hv_defs::HvRegisterValue;

    fn new_platform(
        compatibility_mask: u32,
        platform_type: IgvmPlatformType,
    ) -> IgvmPlatformHeader {
        IgvmPlatformHeader::SupportedPlatform(IGVM_VHS_SUPPORTED_PLATFORM {
            compatibility_mask,
            highest_vtl: 0,
            platform_type,
            platform_version: 1,
            shared_gpa_boundary: 0,
        })
    }

    fn new_page_data(page: u64, compatibility_mask: u32, data: &[u8]) -> IgvmDirectiveHeader {
        IgvmDirectiveHeader::PageData {
            gpa: page * PAGE_SIZE_4K,
            compatibility_mask,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: data.to_vec(),
        }
    }

    fn assert_igvm_equal(a: &IgvmFile, b: &IgvmFile) {
        assert_eq!(a.revision, b.revision);

        for (a, b) in a.platform_headers.iter().zip(b.platform_headers.iter()) {
            assert_eq!(a, b);
        }

        for (a, b) in a
            .initialization_headers
            .iter()
            .zip(b.initialization_headers.iter())
        {
            assert_eq!(a, b);
        }

        for (a, b) in a.directive_headers.iter().zip(b.directive_headers.iter()) {
            assert_eq!(a, b);
        }
    }

    fn new_parameter_area(index: u32) -> IgvmDirectiveHeader {
        IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: 4096,
            parameter_area_index: index,
            initial_data: vec![],
        }
    }

    fn new_parameter_usage(index: u32) -> IgvmDirectiveHeader {
        IgvmDirectiveHeader::VpCount(IGVM_VHS_PARAMETER {
            parameter_area_index: index,
            byte_offset: 0,
        })
    }

    fn new_parameter_insert(page: u64, index: u32, mask: u32) -> IgvmDirectiveHeader {
        IgvmDirectiveHeader::ParameterInsert(IGVM_VHS_PARAMETER_INSERT {
            gpa: page * PAGE_SIZE_4K,
            parameter_area_index: index,
            compatibility_mask: mask,
        })
    }

    mod new_from_binary {
        use super::*;
        // TODO: test individual or extend existing individual tests to match.
        //       pending refactor though for bad get_* methods to take mut vector instead

        // test basic
        #[test]
        fn test_basic() {
            let data1 = vec![1; PAGE_SIZE_4K as usize];
            let data2 = vec![2; PAGE_SIZE_4K as usize];
            let data3 = vec![3; PAGE_SIZE_4K as usize];
            let data4 = vec![4; PAGE_SIZE_4K as usize];
            let file = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::VSM_ISOLATION)],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_page_data(0, 1, &data1),
                    new_page_data(1, 1, &data2),
                    new_page_data(2, 1, &data3),
                    new_page_data(4, 1, &data4),
                    new_page_data(10, 1, &data1),
                    new_page_data(11, 1, &data2),
                    new_page_data(12, 1, &data3),
                    new_page_data(14, 1, &data4),
                    new_parameter_area(0),
                    new_parameter_usage(0),
                    new_parameter_insert(20, 0, 1),
                ],
            };
            let mut binary_file = Vec::new();
            file.serialize(&mut binary_file).unwrap();

            let deserialized_binary_file = IgvmFile::new_from_binary(&binary_file, None).unwrap();
            assert_igvm_equal(&file, &deserialized_binary_file);
        }

        #[test]
        fn test_basic_v2() {
            let data1 = vec![1; PAGE_SIZE_4K as usize];
            let data2 = vec![2; PAGE_SIZE_4K as usize];
            let data3 = vec![3; PAGE_SIZE_4K as usize];
            let data4 = vec![4; PAGE_SIZE_4K as usize];
            let file = IgvmFile {
                revision: IgvmRevision::V2 {
                    arch: Arch::X64,
                    page_size: PAGE_SIZE_4K as u32,
                },
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::VSM_ISOLATION)],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_page_data(0, 1, &data1),
                    new_page_data(1, 1, &data2),
                    new_page_data(2, 1, &data3),
                    new_page_data(4, 1, &data4),
                    new_page_data(10, 1, &data1),
                    new_page_data(11, 1, &data2),
                    new_page_data(12, 1, &data3),
                    new_page_data(14, 1, &data4),
                    new_parameter_area(0),
                    new_parameter_usage(0),
                    new_parameter_insert(20, 0, 1),
                    IgvmDirectiveHeader::X64VbsVpContext {
                        vtl: Vtl::Vtl0,
                        registers: vec![X86Register::R12(0x1234)],
                        compatibility_mask: 0x1,
                    },
                ],
            };
            let mut binary_file = Vec::new();
            file.serialize(&mut binary_file).unwrap();

            let deserialized_binary_file = IgvmFile::new_from_binary(&binary_file, None).unwrap();
            assert_igvm_equal(&file, &deserialized_binary_file);
        }

        #[test]
        fn test_basic_v2_aarch64() {
            let data1 = vec![1; PAGE_SIZE_4K as usize];
            let data2 = vec![2; PAGE_SIZE_4K as usize];
            let data3 = vec![3; PAGE_SIZE_4K as usize];
            let data4 = vec![4; PAGE_SIZE_4K as usize];
            let file = IgvmFile {
                revision: IgvmRevision::V2 {
                    arch: Arch::AArch64,
                    page_size: PAGE_SIZE_4K as u32,
                },
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::VSM_ISOLATION)],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_page_data(0, 1, &data1),
                    new_page_data(1, 1, &data2),
                    new_page_data(2, 1, &data3),
                    new_page_data(4, 1, &data4),
                    new_page_data(10, 1, &data1),
                    new_page_data(11, 1, &data2),
                    new_page_data(12, 1, &data3),
                    new_page_data(14, 1, &data4),
                    new_parameter_area(0),
                    new_parameter_usage(0),
                    new_parameter_insert(20, 0, 1),
                    IgvmDirectiveHeader::AArch64VbsVpContext {
                        vtl: Vtl::Vtl0,
                        registers: vec![AArch64Register::X0(0x1234)],
                        compatibility_mask: 0x1,
                    },
                ],
            };
            let mut binary_file = Vec::new();
            file.serialize(&mut binary_file).unwrap();

            let deserialized_binary_file = IgvmFile::new_from_binary(&binary_file, None).unwrap();
            assert_igvm_equal(&file, &deserialized_binary_file);
        }

        // test platform filter works correctly
        // test state transition checks enforce correct ordering
    }

    mod merge {
        use super::*;

        // test merge function
        #[test]
        fn test_merge_basic() {
            let data1 = vec![1; PAGE_SIZE_4K as usize];
            let data2 = vec![2; PAGE_SIZE_4K as usize];
            let data3 = vec![3; PAGE_SIZE_4K as usize];
            let data4 = vec![4; PAGE_SIZE_4K as usize];
            let mut a = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::VSM_ISOLATION)],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_page_data(0, 1, &data1),
                    new_page_data(1, 1, &data2),
                    new_page_data(2, 1, &data3),
                    new_page_data(4, 1, &data4),
                    new_page_data(10, 1, &data1),
                    new_page_data(11, 1, &data2),
                    new_page_data(12, 1, &data3),
                    new_page_data(14, 1, &data4),
                ],
            };
            let b = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::SEV_SNP)],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_page_data(0, 1, &data1),
                    new_page_data(1, 1, &data2),
                    new_page_data(2, 1, &data3),
                    new_page_data(4, 1, &data4),
                    new_page_data(20, 1, &data1),
                    new_page_data(21, 1, &data2),
                    new_page_data(22, 1, &data3),
                    new_page_data(24, 1, &data4),
                ],
            };
            let merged = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![
                    new_platform(0x1, IgvmPlatformType::VSM_ISOLATION),
                    new_platform(0x2, IgvmPlatformType::SEV_SNP),
                ],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_page_data(0, 3, &data1),
                    new_page_data(1, 3, &data2),
                    new_page_data(2, 3, &data3),
                    new_page_data(4, 3, &data4),
                    new_page_data(20, 2, &data1),
                    new_page_data(21, 2, &data2),
                    new_page_data(22, 2, &data3),
                    new_page_data(24, 2, &data4),
                    new_page_data(10, 1, &data1),
                    new_page_data(11, 1, &data2),
                    new_page_data(12, 1, &data3),
                    new_page_data(14, 1, &data4),
                ],
            };

            a.merge(b).unwrap();
            assert_igvm_equal(&a, &merged);
        }

        // test multiple platform headers with masks gets fixed up
        #[test]
        fn test_multiple_compat_masks() {
            let data1 = vec![1; PAGE_SIZE_4K as usize];
            let data2 = vec![2; PAGE_SIZE_4K as usize];

            // merge igvm file with all 3 isolation types, two with compat mask 0x1 and third with compat mask 0x2
            let mut a = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::VSM_ISOLATION)],
                initialization_headers: vec![],
                directive_headers: vec![new_page_data(0, 1, &data1), new_page_data(1, 1, &data2)],
            };
            let b = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::SEV_SNP)],
                initialization_headers: vec![],
                directive_headers: vec![new_page_data(0, 1, &data1), new_page_data(1, 1, &data2)],
            };
            let c = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![new_platform(0x2, IgvmPlatformType::TDX)],
                initialization_headers: vec![],
                directive_headers: vec![new_page_data(0, 2, &data1), new_page_data(1, 2, &data2)],
            };
            let merged = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![
                    new_platform(0x1, IgvmPlatformType::VSM_ISOLATION),
                    new_platform(0x2, IgvmPlatformType::SEV_SNP),
                    new_platform(0x4, IgvmPlatformType::TDX),
                ],
                initialization_headers: vec![],
                directive_headers: vec![new_page_data(0, 7, &data1), new_page_data(1, 7, &data2)],
            };
            a.merge(b).unwrap();
            a.merge(c).unwrap();
            assert_igvm_equal(&a, &merged);
        }

        // test page imports to same page but different data do not merge
        #[test]
        fn test_merge_page_data_should_not_merge() {
            let data1 = vec![1; PAGE_SIZE_4K as usize];
            let data2 = vec![2; PAGE_SIZE_4K as usize];

            let mut a = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::VSM_ISOLATION)],
                initialization_headers: vec![],
                directive_headers: vec![new_page_data(0, 1, &data2), new_page_data(1, 1, &data1)],
            };
            let b = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::SEV_SNP)],
                initialization_headers: vec![],
                directive_headers: vec![new_page_data(0, 1, &data1), new_page_data(1, 1, &data2)],
            };
            let merged = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![
                    new_platform(0x1, IgvmPlatformType::VSM_ISOLATION),
                    new_platform(0x2, IgvmPlatformType::SEV_SNP),
                ],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_page_data(0, 2, &data1),
                    new_page_data(1, 2, &data2),
                    new_page_data(0, 1, &data2),
                    new_page_data(1, 1, &data1),
                ],
            };

            a.merge(b).unwrap();
            assert_igvm_equal(&a, &merged);
        }

        #[test]
        fn test_merge_stable_ordering() {
            // test stable ordering
            //      test headers that could be merged but would violate stable ordering
            //      test first header matches, very last header matches, all subsequent should just be appended (could possibly match)
            let data1 = vec![1; PAGE_SIZE_4K as usize];
            let data2 = vec![2; PAGE_SIZE_4K as usize];
            let data3 = vec![3; PAGE_SIZE_4K as usize];
            let data4 = vec![4; PAGE_SIZE_4K as usize];
            let mut a = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::VSM_ISOLATION)],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_page_data(0, 1, &data1),
                    new_page_data(1, 1, &data2),
                    new_page_data(2, 1, &data3),
                    new_page_data(4, 1, &data4),
                    new_page_data(10, 1, &data1),
                    new_page_data(11, 1, &data2),
                    new_page_data(12, 1, &data3),
                    new_page_data(14, 1, &data4),
                ],
            };
            let b = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::SEV_SNP)],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_page_data(0, 1, &data1),
                    new_page_data(14, 1, &data4),
                    new_page_data(1, 1, &data2),
                    new_page_data(2, 1, &data3),
                    new_page_data(4, 1, &data4),
                    new_page_data(10, 1, &data1),
                    new_page_data(11, 1, &data2),
                    new_page_data(12, 1, &data3),
                ],
            };
            let merged = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![
                    new_platform(0x1, IgvmPlatformType::VSM_ISOLATION),
                    new_platform(0x2, IgvmPlatformType::SEV_SNP),
                ],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_page_data(0, 3, &data1),
                    new_page_data(1, 1, &data2),
                    new_page_data(2, 1, &data3),
                    new_page_data(4, 1, &data4),
                    new_page_data(10, 1, &data1),
                    new_page_data(11, 1, &data2),
                    new_page_data(12, 1, &data3),
                    new_page_data(14, 3, &data4),
                    new_page_data(1, 2, &data2),
                    new_page_data(2, 2, &data3),
                    new_page_data(4, 2, &data4),
                    new_page_data(10, 2, &data1),
                    new_page_data(11, 2, &data2),
                    new_page_data(12, 2, &data3),
                ],
            };
            a.merge(b).unwrap();
            assert_igvm_equal(&a, &merged);
        }

        #[test]
        fn test_merge_parameter_areas() {
            // test parameter page indexes get changed since merges are not supported
            //      test basic parameter usage
            //      test gaps in parameter indices in src and dest
            //      test parameter areas that do not overlap

            // basic parameter area merging
            let mut a = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::VSM_ISOLATION)],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_parameter_area(1),
                    new_parameter_area(2),
                    new_parameter_area(7),
                    new_parameter_usage(1),
                    new_parameter_usage(2),
                    new_parameter_usage(7),
                    new_parameter_insert(1, 1, 1),
                    new_parameter_insert(2, 2, 1),
                    new_parameter_insert(10, 7, 1),
                ],
            };

            let b = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![new_platform(0x1, IgvmPlatformType::SEV_SNP)],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_parameter_area(1),
                    new_parameter_area(2),
                    new_parameter_area(10),
                    new_parameter_usage(1),
                    new_parameter_usage(2),
                    new_parameter_usage(10),
                    new_parameter_insert(1, 1, 1),
                    new_parameter_insert(4, 2, 1),
                    new_parameter_insert(12, 10, 1),
                ],
            };

            let merged = IgvmFile {
                revision: IgvmRevision::V1,
                platform_headers: vec![
                    new_platform(0x1, IgvmPlatformType::VSM_ISOLATION),
                    new_platform(0x2, IgvmPlatformType::SEV_SNP),
                ],
                initialization_headers: vec![],
                directive_headers: vec![
                    new_parameter_area(0),
                    new_parameter_area(3),
                    new_parameter_area(10),
                    new_parameter_usage(0),
                    new_parameter_usage(3),
                    new_parameter_usage(10),
                    new_parameter_insert(1, 0, 2),
                    new_parameter_insert(4, 3, 2),
                    new_parameter_insert(12, 10, 2),
                    new_parameter_area(1),
                    new_parameter_area(2),
                    new_parameter_area(7),
                    new_parameter_usage(1),
                    new_parameter_usage(2),
                    new_parameter_usage(7),
                    new_parameter_insert(1, 1, 1),
                    new_parameter_insert(2, 2, 1),
                    new_parameter_insert(10, 7, 1),
                ],
            };

            a.merge(b).unwrap();
            assert_igvm_equal(&a, &merged);
        }
    }

    // TODO: test validate platform headers
    //       test validate directive headers
    //
    //       test headers equivalent function

    /// Test a variable header matches the supplied args. Also tests that the header deserialized returns the original
    /// header.
    fn test_variable_header<T: FromBytesExt>(
        revision: IgvmRevision,
        header: IgvmDirectiveHeader,
        file_data_offset: u32,
        header_type: IgvmVariableHeaderType,
        expected_variable_binary_header: T,
        expected_file_data: Option<Vec<u8>>,
        platform_to_report: Option<IgvmPlatformType>,
    ) {
        let mut binary_header = Vec::new();
        let mut file_data = Vec::new();

        header
            .write_binary_header(file_data_offset, &mut binary_header, &mut file_data)
            .unwrap();

        let common_header = IGVM_VHS_VARIABLE_HEADER::read_from_prefix(&binary_header[..])
            .expect("variable header must be present");

        assert_eq!(common_header.typ, header_type);
        assert_eq!(
            align_8(common_header.length as usize),
            size_of_val(&expected_variable_binary_header)
        );
        assert_eq!(
            &binary_header[size_of_val(&common_header)..],
            expected_variable_binary_header.as_bytes()
        );

        match &expected_file_data {
            Some(data) => assert_eq!(data, &file_data),
            None => assert!(file_data.is_empty()),
        }

        let (reserialized_header, remaining) = IgvmDirectiveHeader::new_from_binary_split(
            revision,
            &binary_header,
            &file_data,
            file_data_offset,
            |_mask| platform_to_report,
        )
        .unwrap();
        assert!(remaining.is_empty());

        // Reserialized header should match the initial supplied one, with some differences for data padding.
        match (&header, &reserialized_header) {
            (
                IgvmDirectiveHeader::PageData {
                    gpa: a_gpa,
                    flags: a_flags,
                    data_type: a_data_type,
                    data: a_data,
                    compatibility_mask: a_compmask,
                },
                IgvmDirectiveHeader::PageData {
                    gpa: b_gpa,
                    flags: b_flags,
                    data_type: b_data_type,
                    data: b_data,
                    compatibility_mask: b_compmask,
                },
            ) => {
                assert!(
                    a_gpa == b_gpa
                        && a_flags == b_flags
                        && a_data_type == b_data_type
                        && a_compmask == b_compmask
                );

                // data might not be the same length, as it gets padded out.
                for i in 0..b_data.len() {
                    if i < a_data.len() {
                        assert_eq!(a_data[i], b_data[i]);
                    } else {
                        assert_eq!(0, b_data[i]);
                    }
                }
            }
            (
                IgvmDirectiveHeader::ParameterArea {
                    number_of_bytes: a_number_of_bytes,
                    parameter_area_index: a_parameter_area_index,
                    initial_data: a_initial_data,
                },
                IgvmDirectiveHeader::ParameterArea {
                    number_of_bytes: b_number_of_bytes,
                    parameter_area_index: b_parameter_area_index,
                    initial_data: b_initial_data,
                },
            ) => {
                assert!(
                    a_number_of_bytes == b_number_of_bytes
                        && a_parameter_area_index == b_parameter_area_index
                );

                // initial_data might be padded out just like page data.
                for i in 0..b_initial_data.len() {
                    if i < a_initial_data.len() {
                        assert_eq!(a_initial_data[i], b_initial_data[i]);
                    } else {
                        assert_eq!(0, b_initial_data[i]);
                    }
                }
            }
            _ => assert_eq!(header, reserialized_header),
        }
    }

    // Test get binary header for each type.
    #[test]
    fn test_page_data() {
        let gpa = 0x12 * PAGE_SIZE_4K;
        let file_data_offset = 0x12340;

        // Test empty page data
        let header = IgvmDirectiveHeader::PageData {
            gpa,
            compatibility_mask: 0,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: vec![],
        };
        let expected_header = IGVM_VHS_PAGE_DATA {
            gpa,
            ..FromZeroes::new_zeroed()
        };
        test_variable_header(
            IgvmRevision::V1,
            header,
            file_data_offset,
            IgvmVariableHeaderType::IGVM_VHT_PAGE_DATA,
            expected_header,
            None,
            None,
        );

        // Test sub 4k page data
        let mut data = vec![1, 2, 3, 4, 5, 4, 3, 2, 1];
        let header = IgvmDirectiveHeader::PageData {
            gpa,
            compatibility_mask: 0,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: data.clone(),
        };
        let expected_header = IGVM_VHS_PAGE_DATA {
            gpa,
            file_offset: file_data_offset,
            ..FromZeroes::new_zeroed()
        };
        data.resize(PAGE_SIZE_4K as usize, 0);
        let expected_file_data = Some(data);
        test_variable_header(
            IgvmRevision::V1,
            header,
            file_data_offset,
            IgvmVariableHeaderType::IGVM_VHT_PAGE_DATA,
            expected_header,
            expected_file_data,
            None,
        );

        // Test exactly 4k page data
        let data: Vec<u8> = (0..PAGE_SIZE_4K).map(|x| (x % 255) as u8).collect();
        let header = IgvmDirectiveHeader::PageData {
            gpa,
            compatibility_mask: 0,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: data.clone(),
        };
        let expected_header = IGVM_VHS_PAGE_DATA {
            gpa,
            file_offset: file_data_offset,
            ..FromZeroes::new_zeroed()
        };
        let expected_file_data = Some(data);
        test_variable_header(
            IgvmRevision::V1,
            header,
            file_data_offset,
            IgvmVariableHeaderType::IGVM_VHT_PAGE_DATA,
            expected_header,
            expected_file_data,
            None,
        );
    }

    #[test]
    fn test_page_data_over_4k() {
        // TODO: once we support 2MB page datas, this will need to be fixed.
        let size = PAGE_SIZE_4K as usize + 1;
        let header = IgvmDirectiveHeader::PageData {
            gpa: 0,
            compatibility_mask: 1,
            flags: IgvmPageDataFlags::new(),
            data_type: IgvmPageDataType::NORMAL,
            data: vec![0; size],
        };

        match header.write_binary_header(1000, &mut Vec::new(), &mut Vec::new()) {
            Err(BinaryHeaderError::InvalidDataSize) => {}
            _ => {
                panic!("invalid serialization")
            }
        }
    }

    #[test]
    fn test_parameter_area() {
        let file_data_offset = 1234;

        // Test single page
        let raw_header = IGVM_VHS_PARAMETER_AREA {
            number_of_bytes: PAGE_SIZE_4K,
            parameter_area_index: 2,
            file_offset: 0,
        };

        let header = IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: PAGE_SIZE_4K,
            parameter_area_index: 2,
            initial_data: Vec::new(),
        };
        test_variable_header(
            IgvmRevision::V1,
            header,
            0,
            IgvmVariableHeaderType::IGVM_VHT_PARAMETER_AREA,
            raw_header,
            None,
            None,
        );

        let raw_header = IGVM_VHS_PARAMETER_AREA {
            number_of_bytes: PAGE_SIZE_4K,
            parameter_area_index: 2,
            file_offset: file_data_offset,
        };
        let mut file_data = vec![1, 2, 3, 4, 5, 0, 1];
        let header = IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: PAGE_SIZE_4K,
            parameter_area_index: 2,
            initial_data: file_data.clone(),
        };
        file_data.resize(PAGE_SIZE_4K as usize, 0);
        test_variable_header(
            IgvmRevision::V1,
            header,
            file_data_offset,
            IgvmVariableHeaderType::IGVM_VHT_PARAMETER_AREA,
            raw_header,
            Some(file_data),
            None,
        );

        // Test multi page
        let raw_header = IGVM_VHS_PARAMETER_AREA {
            number_of_bytes: 123 * PAGE_SIZE_4K,
            parameter_area_index: 2,
            file_offset: 0,
        };

        let header = IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: 123 * PAGE_SIZE_4K,
            parameter_area_index: 2,
            initial_data: Vec::new(),
        };
        test_variable_header(
            IgvmRevision::V1,
            header,
            0,
            IgvmVariableHeaderType::IGVM_VHT_PARAMETER_AREA,
            raw_header,
            None,
            None,
        );

        let raw_header = IGVM_VHS_PARAMETER_AREA {
            number_of_bytes: 123 * PAGE_SIZE_4K,
            parameter_area_index: 2,
            file_offset: file_data_offset,
        };
        let mut file_data: Vec<u8> = (0..(PAGE_SIZE_4K + 1482))
            .map(|x| (x % 255) as u8)
            .collect();
        let header = IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: 123 * PAGE_SIZE_4K,
            parameter_area_index: 2,
            initial_data: file_data.clone(),
        };
        file_data.resize(123 * PAGE_SIZE_4K as usize, 0);
        test_variable_header(
            IgvmRevision::V1,
            header,
            file_data_offset,
            IgvmVariableHeaderType::IGVM_VHT_PARAMETER_AREA,
            raw_header,
            Some(file_data),
            None,
        );
    }

    #[test]
    fn test_parameter_area_bad_size() {
        // Non page size number of bytes
        let header = IgvmDirectiveHeader::ParameterArea {
            number_of_bytes: 1234,
            parameter_area_index: 0,
            initial_data: Vec::new(),
        };

        assert!(matches!(
            header.write_binary_header(1000, &mut Vec::new(), &mut Vec::new()),
            Err(BinaryHeaderError::UnalignedSize(1234))
        ));
    }

    /// Generate a test function to test an IGVM parameter directive type.
    macro_rules! test_igvm_parameter {
        ($test_name:ident($directive:path, $header_type:path)) => {
            #[test]
            fn $test_name() {
                // Byte offset 0
                let raw_header = IGVM_VHS_PARAMETER {
                    parameter_area_index: 1,
                    byte_offset: 0,
                };
                let header = $directive(raw_header);
                test_variable_header(
                    IgvmRevision::V1,
                    header,
                    0,
                    $header_type,
                    raw_header,
                    None,
                    None,
                );

                // Byte offset 1234
                let raw_header = IGVM_VHS_PARAMETER {
                    parameter_area_index: 0,
                    byte_offset: 1234,
                };
                let header = $directive(raw_header);
                test_variable_header(
                    IgvmRevision::V1,
                    header,
                    0,
                    $header_type,
                    raw_header,
                    None,
                    None,
                );
            }
        };
    }

    test_igvm_parameter!(test_vp_count(
        IgvmDirectiveHeader::VpCount,
        IgvmVariableHeaderType::IGVM_VHT_VP_COUNT_PARAMETER
    ));

    test_igvm_parameter!(test_environment_info(
        IgvmDirectiveHeader::EnvironmentInfo,
        IgvmVariableHeaderType::IGVM_VHT_ENVIRONMENT_INFO_PARAMETER
    ));

    test_igvm_parameter!(test_srat(
        IgvmDirectiveHeader::Srat,
        IgvmVariableHeaderType::IGVM_VHT_SRAT
    ));

    test_igvm_parameter!(test_madt(
        IgvmDirectiveHeader::Madt,
        IgvmVariableHeaderType::IGVM_VHT_MADT
    ));

    test_igvm_parameter!(test_slit(
        IgvmDirectiveHeader::Slit,
        IgvmVariableHeaderType::IGVM_VHT_SLIT
    ));

    test_igvm_parameter!(test_pptt(
        IgvmDirectiveHeader::Pptt,
        IgvmVariableHeaderType::IGVM_VHT_PPTT
    ));

    test_igvm_parameter!(test_mmio_ranges(
        IgvmDirectiveHeader::MmioRanges,
        IgvmVariableHeaderType::IGVM_VHT_MMIO_RANGES
    ));

    test_igvm_parameter!(test_memory_map(
        IgvmDirectiveHeader::MemoryMap,
        IgvmVariableHeaderType::IGVM_VHT_MEMORY_MAP
    ));

    test_igvm_parameter!(test_command_line(
        IgvmDirectiveHeader::CommandLine,
        IgvmVariableHeaderType::IGVM_VHT_COMMAND_LINE
    ));

    #[test]
    fn test_required_memory() {
        let gpa = 0x1234 * PAGE_SIZE_4K;
        let number_of_bytes = 0x4567 * PAGE_SIZE_4K as u32;
        let compatibility_mask = 0x1;
        let vtl2_protectable = true;
        let flags = RequiredMemoryFlags::new().with_vtl2_protectable(true);
        let raw_header = IGVM_VHS_REQUIRED_MEMORY {
            gpa,
            number_of_bytes,
            compatibility_mask,
            flags,
            ..FromZeroes::new_zeroed()
        };

        let header = IgvmDirectiveHeader::RequiredMemory {
            gpa,
            number_of_bytes,
            compatibility_mask,
            vtl2_protectable,
        };
        test_variable_header(
            IgvmRevision::V1,
            header,
            0,
            IgvmVariableHeaderType::IGVM_VHT_REQUIRED_MEMORY,
            raw_header,
            None,
            None,
        );

        let gpa = 24 * 1024 * 1024;
        let number_of_bytes = 64 * 1024 * 1024;
        let compatibility_mask = 0x1;
        let flags = RequiredMemoryFlags::new();
        let raw_header = IGVM_VHS_REQUIRED_MEMORY {
            gpa,
            number_of_bytes,
            compatibility_mask,
            flags,
            ..FromZeroes::new_zeroed()
        };

        let header = IgvmDirectiveHeader::RequiredMemory {
            gpa,
            number_of_bytes,
            compatibility_mask,
            vtl2_protectable: false,
        };
        test_variable_header(
            IgvmRevision::V1,
            header,
            0,
            IgvmVariableHeaderType::IGVM_VHT_REQUIRED_MEMORY,
            raw_header,
            None,
            None,
        );
    }

    #[test]
    fn test_required_memory_unaligned_gpa() {
        let gpa = 0x1234;

        let header = IgvmDirectiveHeader::RequiredMemory {
            gpa,
            number_of_bytes: 0x4567 * PAGE_SIZE_4K as u32,
            compatibility_mask: 0x1,
            vtl2_protectable: true,
        };
        match header.write_binary_header(1234, &mut Vec::new(), &mut Vec::new()) {
            Err(BinaryHeaderError::UnalignedAddress(err_gpa)) => {
                assert_eq!(gpa, err_gpa);
            }
            _ => panic!("invalid serialization"),
        }
    }

    #[test]
    fn test_required_memory_unaligned_size() {
        let size = 0x4567;

        let header = IgvmDirectiveHeader::RequiredMemory {
            gpa: 0x1234 * PAGE_SIZE_4K,
            number_of_bytes: size,
            compatibility_mask: 0x1,
            vtl2_protectable: true,
        };
        match header.write_binary_header(1234, &mut Vec::new(), &mut Vec::new()) {
            Err(BinaryHeaderError::UnalignedSize(err_size)) => {
                assert_eq!(size as u64, err_size);
            }
            _ => panic!("invalid serialization"),
        }
    }

    #[test]
    fn test_parameter_insert() {
        let raw_header = IGVM_VHS_PARAMETER_INSERT {
            gpa: 0x1234 * PAGE_SIZE_4K,
            compatibility_mask: 0x1,
            parameter_area_index: 0x10,
        };

        let header = IgvmDirectiveHeader::ParameterInsert(raw_header);
        test_variable_header(
            IgvmRevision::V1,
            header,
            1234,
            IgvmVariableHeaderType::IGVM_VHT_PARAMETER_INSERT,
            raw_header,
            None,
            None,
        );
    }

    #[test]
    fn test_parameter_insert_unaligned_gpa() {
        let gpa = 0x1234;
        let raw_header = IGVM_VHS_PARAMETER_INSERT {
            gpa,
            compatibility_mask: 0x1,
            parameter_area_index: 0x10,
        };

        let header = IgvmDirectiveHeader::ParameterInsert(raw_header);
        match header.write_binary_header(1234, &mut Vec::new(), &mut Vec::new()) {
            Err(BinaryHeaderError::UnalignedAddress(err_gpa)) => {
                assert_eq!(gpa, err_gpa);
            }
            _ => panic!("invalid serialization"),
        }
    }

    #[test]
    fn test_aarch64_vbs_vp_context() {
        let raw_header = IGVM_VHS_VP_CONTEXT {
            gpa: 0.into(),
            compatibility_mask: 0x1,
            file_offset: 1234,
            vp_index: 0,
            reserved: 0,
        };

        let mut raw_header_bytes: [u8; 24] = [0; 24];
        raw_header_bytes[..raw_header.as_bytes().len()].copy_from_slice(raw_header.as_bytes());

        let reg_list = [
            VbsVpContextRegister {
                vtl: 0,
                register_name: HvArm64RegisterName::XPc.0.into(),
                mbz: [0; 11],
                register_value: HvRegisterValue::from(0x1234u64).0.to_ne_bytes(),
            },
            VbsVpContextRegister {
                vtl: 0,
                register_name: HvArm64RegisterName::X1.0.into(),
                mbz: [0; 11],
                register_value: HvRegisterValue::from(0x5678u64).0.to_ne_bytes(),
            },
        ];

        let reg_header = VbsVpContextHeader { register_count: 2 };
        let mut file_data: Vec<u8> = Vec::new();
        file_data.extend_from_slice(reg_header.as_bytes());
        file_data.extend_from_slice(reg_list.as_bytes());

        let header = IgvmDirectiveHeader::AArch64VbsVpContext {
            vtl: Vtl::Vtl0,
            registers: vec![AArch64Register::Pc(0x1234), AArch64Register::X1(0x5678)],
            compatibility_mask: 0x1,
        };

        test_variable_header(
            IgvmRevision::V2 {
                arch: Arch::AArch64,
                page_size: PAGE_SIZE_4K as u32,
            },
            header,
            1234,
            IgvmVariableHeaderType::IGVM_VHT_VP_CONTEXT,
            raw_header_bytes,
            Some(file_data),
            Some(IgvmPlatformType::VSM_ISOLATION),
        )
    }
    // Test SNP vp context

    // Test serialize and deserialize
}
