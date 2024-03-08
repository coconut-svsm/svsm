// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! This crate provides the definitions for the Independent Guest Virtual
//! Machine (IGVM) file format.
//!
//! The IGVM file format is designed to encapsulate all information required to
//! launch a virtual machine on any given virtualization stack, with support for
//! different isolation technologies such as AMD SEV-SNP and Intel TDX.
//!
//! At a conceptual level, this file format is a set of commands created by the
//! tool that generated the file, used by the loader to construct the initial
//! guest state. The file format also contains measurement information that the
//! underlying platform will use to confirm that the file was loaded correctly
//! and signed by the appropriate authorities.
//!
//! This crate is available as no_std.
//!
//! # Structure
//! An IGVM file consists of three regions: the fixed header, the variable
//! header, and file data.
//!
//! The endianness of the IGVM file and any byte contents is little endian.
//!
//! FUTURE: Include sample valid file, expected behavior, and table images.
//!
//! ## Fixed Header
//! The fixed header is defined by the [`IGVM_FIXED_HEADER`] structure. This
//! structure is always at the start of the file.
//!
//! Note: Version 2 and future versions of the file format will use the
#![cfg_attr(feature = "unstable", doc = "[`IGVM_FIXED_HEADER_V2`]")]
#![cfg_attr(not(feature = "unstable"), doc = "`IGVM_FIXED_HEADER_V2`")]
//!
//! ### Version 2 work-in-progress
//!
//! Version 2 supports specifying the architecture along with page size referred
//! to by the file.
//!
//! Version 2 definitions can be used via the `unstable` feature.
//!
//! ## Variable Header
//! The variable header is a list of different TLV (Type, Length, Value) data
//! structures.  Each structure is prefaced by a 32-bit type field and a 32-bit
//! length field as described by the [`IGVM_VHS_VARIABLE_HEADER`], and the
//! content of each structure is determined by its type. The high bit of the
//! type field indicates whether the structure can be ignored by a loader that
//! does not support the structure type; if it is clear and the loader does not
//! support the type, then the file cannot be loaded.
//!
//! Each variable header structure must be fully contained within the size of
//! the variable header described in the fixed header.  The length field of each
//! variable header structure describes only the content within the structure,
//! and not the 8 bytes of type/length information.  Each variable header
//! structure must begin at a file offset that is a multiple of 8 bytes, so the
//! length field of any structure must be rounded up to 8 bytes to find the
//! type/length information of the following structure. The padding used to
//! align each variable header to 8 byte alignments must be zero.
//!
//! Variable headers can be divided into three different sections, platform,
//! initialization, directives. Platform types define the compatibility masks
//! and supported platforms for the file, initialization defines the early data
//! needed by individual hardware platforms to prepare the guest partition to
//! accept data, and directives are the actual commands for the loader to load
//! data into the guest from the file and runtime parameters.
//!
//! Variable headers must not appear in a later section after making a section
//! transition. Loaders make a state transition from platform to initialization
//! headers once the first initialization header type is read. The same applies
//! for the transition from initialization to directives. For example, once the
//! first initialization header is read, it is no longer valid for the file to
//! specify any additional platform headers.
//!
//! Types are defined by [`IgvmVariableHeaderType`].
//!
//! Except for a few specific structure types, each structure indicates to the
//! loader that the data specified by the structure should be added to the guest
//! immediately, in order to reach the same end measurement as specified by the
//! file.
//!
//! ## File Data
//! The file data has no specific structure.  Portions of the file data are
//! consumed through references made from the header structures.
//!
//! # Revisions
//!
//! Version 2 of the specification is currently a work in progress. Those
//! definitions can be enabled with the `unstable` feature.

#![no_std]
#![warn(missing_docs)]
#![deny(unsafe_code)]
// Enables the `doc_cfg` feature when the `docsrs` configuration attribute
// is defined.
#![cfg_attr(docsrs, feature(doc_cfg))]
// IGVM header types are spec defined as upper case.
#![allow(clippy::upper_case_acronyms)]
// IGVM types are defined in C style.
#![allow(non_camel_case_types)]

use self::packed_nums::*;
use bitfield_struct::bitfield;
use core::mem::size_of;
use open_enum::open_enum;
use static_assertions::const_assert_eq;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

pub mod dt;

#[allow(non_camel_case_types)]
mod packed_nums {
    pub type u32_le = zerocopy::U32<zerocopy::LittleEndian>;
    pub type u64_le = zerocopy::U64<zerocopy::LittleEndian>;
}

/// The version 1 fixed header that is at the start of every IGVM file.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct IGVM_FIXED_HEADER {
    /// A u32 that must hold the value described by [`IGVM_MAGIC_VALUE`].
    pub magic: u32,
    /// Describes the version of the file format that must be supported by the
    /// loader in order for this file to load successfully.
    pub format_version: u32,
    /// Describes the byte offset to the variable header in the file. This must be
    /// greater than or equal to the size of the fixed header, and must be
    /// aligned to an 8-byte boundary.
    pub variable_header_offset: u32,
    /// Describes the total size in bytes of the variable header in the file.
    pub variable_header_size: u32,
    /// Describes the total size of the file in bytes.
    pub total_file_size: u32,
    /// Contains a CRC32 that spans the fixed and variable header, but not the
    /// file data section. The checksum is calculated as if this checksum field
    /// is zero.
    pub checksum: u32,
}

/// The version 2 fixed header that is at the start of every IGVM file with
/// format_version >= 2.
///
/// NOTE: This header and the V2 extensions to the format are currently a
/// work-in-progress.
#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct IGVM_FIXED_HEADER_V2 {
    /// A u32 that must hold the value described by [`IGVM_MAGIC_VALUE`].
    pub magic: u32,
    /// Describes the version of the file format that must be supported by the
    /// loader in order for this file to load successfully.
    ///
    /// This must be at least 2.
    pub format_version: u32,
    /// Describes the byte offset to the variable header in the file. This must be
    /// greater than or equal to the size of the fixed header, and must be
    /// aligned to an 8-byte boundary.
    pub variable_header_offset: u32,
    /// Describes the total size in bytes of the variable header in the file.
    pub variable_header_size: u32,
    /// Describes the total size of the file in bytes.
    pub total_file_size: u32,
    /// Contains a CRC32 that spans the fixed and variable header, but not the
    /// file data section. The checksum is calculated as if this checksum field
    /// is zero.
    pub checksum: u32,
    /// The architecture for this IGVM file, as described by
    /// [`IgvmArchitecture`].
    pub architecture: IgvmArchitecture,
    /// The page size used by this IGVM file. This modifies any structure that
    /// refers to page size to refer to this value. By default and in version 1
    /// of the file format, this value is 4K (4096) bytes.
    ///
    /// This value must be a power of 2.
    ///
    /// TODO: Define how a loader that supports a page size less than the one
    /// indicated here could load. For example, an IGVM file with page size 64K
    /// with a loader that supports 4K. Launch measurements may be different,
    /// but we could define different measurement structures based on page size
    /// supported by the loader.
    pub page_size: u32,
}

/// The magic value of `0x4D564749` that must be present in the
/// [`IGVM_FIXED_HEADER`]. This is ASCII `IGVM` in little-endian.
pub const IGVM_MAGIC_VALUE: u32 = u32::from_le_bytes(*b"IGVM");
static_assertions::const_assert_eq!(IGVM_MAGIC_VALUE, 0x4D564749);

/// IGVM format version 1.
pub const IGVM_FORMAT_VERSION_1: u32 = 0x1;

/// IGVM format version 2. This is work-in-progress and not stabilized.
#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
pub const IGVM_FORMAT_VERSION_2: u32 = 0x2;

/// A page size of 4K (4096) bytes.
pub const PAGE_SIZE_4K: u64 = 4096;

/// The architecture described by the fixed header.
#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
#[open_enum]
#[derive(AsBytes, FromBytes, FromZeroes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IgvmArchitecture {
    /// Corresponds to x86-64 / AMD64, 64 bit x86.
    X64 = 0x0,
    /// Corresponds to AArch64 / ARM64.
    AARCH64 = 0x1,
}

// TODO: The format_version in the fixed_header should describe the required
//       minimum version of the file. The loader should be free to ignore
//       additional headers it does not understand. The file builder is required
//       to set the format_version to the correct minimum version required to
//       boot. Maybe IGVM_FIXED_HEADER_EXTENSION?
//
// TODO: We need to determine which set of headers are part of each version somehow.
/// The type of each structure in the variable header section.
///
/// The top bit of this type may be set to indicate a loader may safely ignore
/// that structure.
#[open_enum]
#[derive(AsBytes, FromBytes, FromZeroes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IgvmVariableHeaderType {
    /// Invalid.
    INVALID = 0x0,
    // These are IGVM_VHT_RANGE_PLATFORM structures.
    /// A supported platform structure described by
    /// [`IGVM_VHS_SUPPORTED_PLATFORM`].
    IGVM_VHT_SUPPORTED_PLATFORM = 0x1,

    // These are IGVM_VHT_RANGE_INIT structures.
    /// The isolation architecture policy for the guest, as defined by
    /// [`IGVM_VHS_GUEST_POLICY`].
    IGVM_VHT_GUEST_POLICY = 0x101,
    /// A relocatable region structure described by
    /// [`IGVM_VHS_RELOCATABLE_REGION`]. This is supported on X64 only.
    IGVM_VHT_RELOCATABLE_REGION = 0x102,
    /// A page table relocation region described by
    /// [`IGVM_VHS_PAGE_TABLE_RELOCATION`]. This is supported on X64 only.
    IGVM_VHT_PAGE_TABLE_RELOCATION_REGION = 0x103,

    // These are IGVM_VHT_RANGE_DIRECTIVE structures.
    /// A parameter area structure described by [`IGVM_VHS_PARAMETER_AREA`].
    IGVM_VHT_PARAMETER_AREA = 0x301,
    /// A page data structure described by [`IGVM_VHS_PAGE_DATA`].
    IGVM_VHT_PAGE_DATA = 0x302,
    /// A parameter insert structure described by
    /// [`IGVM_VHS_PARAMETER_INSERT`].
    IGVM_VHT_PARAMETER_INSERT = 0x303,
    /// A VP context structure described by [`IGVM_VHS_VP_CONTEXT`].
    IGVM_VHT_VP_CONTEXT = 0x304,
    /// A required memory structure described by
    /// [`IGVM_VHS_REQUIRED_MEMORY`].
    IGVM_VHT_REQUIRED_MEMORY = 0x305,
    /// Was previously used in earlier revisions as
    /// `IGVM_VHT_SHARED_BOUNDARY_GPA` but is now unused. Do not use for
    /// future revisions.
    RESERVED_DO_NOT_USE = 0x306,
    /// A parameter which holds a 4-byte u32 value defining the number of
    /// VPs that the host intends to start. The loader will write the VP
    /// count to the specified offset of the specified parameter area. The
    /// parameter location information is specified by a structure of type
    /// [`IGVM_VHS_PARAMETER`].
    IGVM_VHT_VP_COUNT_PARAMETER = 0x307,
    /// A parameter where the loader will deposit the ACPI SRAT
    /// table describing topology information as specified by a structure of
    /// type [`IGVM_VHS_PARAMETER`].
    IGVM_VHT_SRAT = 0x308,
    /// A parameter where the loader will deposit the ACPI MADT table
    /// describing CPU topology information as specified by a structure of
    /// type [`IGVM_VHS_PARAMETER`].
    IGVM_VHT_MADT = 0x309,
    /// A parameter where the loader will deposit the mmio ranges of the
    /// guest as specified by [`IGVM_VHS_PARAMETER`].
    ///
    /// The format of the MMIO ranges written by the loader are defined as
    /// [`IGVM_VHS_MMIO_RANGES`].
    IGVM_VHT_MMIO_RANGES = 0x30A,
    /// The AMD SEV-SNP ID block to be used described by
    /// [`IGVM_VHS_SNP_ID_BLOCK`].
    IGVM_VHT_SNP_ID_BLOCK = 0x30B,
    /// A parameter where the loader will deposit the memory available to the
    /// guest as specified by [`IGVM_VHS_PARAMETER`].
    ///
    /// The format of the memory information written by the loader will be
    /// an array of [`IGVM_VHS_MEMORY_MAP_ENTRY`] structures.
    IGVM_VHT_MEMORY_MAP = 0x30C,
    /// An error range structure described by [`IGVM_VHS_ERROR_RANGE`].
    IGVM_VHT_ERROR_RANGE = 0x30D,
    /// A parameter which describes a null terminated ASCII command line to
    /// be used with the guest as specified by [`IGVM_VHS_PARAMETER`]. The
    /// format of the command line is specific to the guest being loaded.
    ///
    /// For example, this parameter could be used to describe the Linux
    /// kernel command line.
    ///
    /// In the [`IgvmVariableHeaderType::IGVM_VHT_DEVICE_TREE`] parameter,
    /// this corresponds to the `/chosen/bootargs` field.
    IGVM_VHT_COMMAND_LINE = 0x30E,
    /// A parameter where the loader will deposit the ACPI SLIT table
    /// describing topology information as specified by a structure of type
    /// [`IGVM_VHS_PARAMETER`].
    IGVM_VHT_SLIT = 0x30F,
    /// A parameter where the loader will deposit the ACPI PPTT table
    /// describing processor topology information as specified by a
    /// structure of type [`IGVM_VHS_PARAMETER`].
    IGVM_VHT_PPTT = 0x310,
    /// A VBS measurement structure described by
    /// [`IGVM_VHS_VBS_MEASUREMENT`].
    IGVM_VHT_VBS_MEASUREMENT = 0x311,
    /// A parameter which contains a full description of the guest partition
    /// in the Flattened Device Tree (DTB) format, as defined by the Device
    /// Tree specification. The intention of this parameter is to supersede
    /// all previous parameter types, and allow for the host to report new
    /// additional information without requiring a new IGVM parameter type,
    /// and a corresponding IGVM specification update. Thus, a guest should
    /// be able to get all host parameter information by creating an IGVM
    /// file with this parameter only. No new IGVM parameter types should be
    /// added.
    ///
    /// Device tree definitions follow standard definitions in the device
    /// tree specification, or Linux definitions defined in the kernel tree
    /// under device tree bindings for specific devices.
    ///
    /// IGVM specific extensions can be found in the [`dt`] module.
    IGVM_VHT_DEVICE_TREE = 0x312,
    /// A parameter which holds a u32 bitfield value defining environmental
    /// state of the VM.  The bitfield is defined by the `IgvmEnvironmentInfo`
    /// structure.  The loader will write the state to the specified offset of
    /// the specified parameter area.  The parameter location information is
    /// specified by a structure of type [`IGVM_VHS_PARAMETER`].
    #[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
    IGVM_VHT_ENVIRONMENT_INFO_PARAMETER = 0x313,
}

/// The range of header types for platform structures.
pub const IGVM_VHT_RANGE_PLATFORM: core::ops::RangeInclusive<u32> = 0x1..=0x100;
/// The range of header types for initialization structures.
pub const IGVM_VHT_RANGE_INIT: core::ops::RangeInclusive<u32> = 0x101..=0x200;
/// The range of header types for directive structures.
pub const IGVM_VHT_RANGE_DIRECTIVE: core::ops::RangeInclusive<u32> = 0x301..=0x400;

/// The header describing each structure in the variable header section. Headers
/// are aligned to 8 byte boundaries.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct IGVM_VHS_VARIABLE_HEADER {
    /// The type of the header.
    pub typ: IgvmVariableHeaderType,
    /// The length of the header. Note that this might not be 8 byte aligned,
    /// but instead describes the size of the content within the structure.
    pub length: u32,
}

/// Enum describing different isolation platforms for
/// [`IGVM_VHS_SUPPORTED_PLATFORM`] structures.
#[open_enum]
#[derive(AsBytes, FromBytes, FromZeroes, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IgvmPlatformType {
    /// Invalid platform type.
    INVALID = 0x00,
    /// Platform type of Hyper-V's which supports VSM isolation.
    VSM_ISOLATION = 0x01,
    /// AMD SEV-SNP.
    SEV_SNP = 0x02,
    /// Intel TDX.
    TDX = 0x03,
}

impl Default for IgvmPlatformType {
    fn default() -> Self {
        IgvmPlatformType::INVALID
    }
}

/// Platform version for [`IgvmPlatformType::VSM_ISOLATION`].
pub const IGVM_VSM_ISOLATION_PLATFORM_VERSION: u16 = 0x1;
/// Platform version for [`IgvmPlatformType::SEV_SNP`].
pub const IGVM_SEV_SNP_PLATFORM_VERSION: u16 = 0x1;
/// Platform version for [`IgvmPlatformType::TDX`].
pub const IGVM_TDX_PLATFORM_VERSION: u16 = 0x1;

/// This structure indicates which isolation platforms are compatible with this
/// guest image. A separate [`IGVM_VHS_SUPPORTED_PLATFORM`] structure must be
/// used for each compatible platform.
///
/// The [`IGVM_VHS_SUPPORTED_PLATFORM`] structure must appear in the header
/// prior to any other structures that refer to the compatibility mask that this
/// structure defines.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_SUPPORTED_PLATFORM {
    /// A bitmask that is used in following variable header structures that
    /// correspond with this platform. Headers that have this corresponding bit
    /// set indicates that it should be loaded if loading this specified
    /// platform.
    ///
    /// This must have only one bit set.
    pub compatibility_mask: u32,
    /// Which VTL will be the highest VTL activated for the guest. On platforms
    /// that do not support multiple VTLs, this value must be zero.
    pub highest_vtl: u8,
    /// Which platform is supported, as defined by [`IgvmPlatformType`].
    pub platform_type: IgvmPlatformType,
    /// The platform version.
    pub platform_version: u16,
    /// This field describes the GPA at which memory above the boundary will be
    /// host visible. A value of 0 indicates that this field is ignored, and the
    /// platform described will manage shared memory in an enlightened manner.
    pub shared_gpa_boundary: u64,
}

/// This structure defines the guest policy that is isolation architecture
/// dependent.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_GUEST_POLICY {
    /// The specified policy which is isolation architecture dependent.
    ///
    /// For AMD SEV-SNP, this is [`SnpPolicy`].
    ///
    /// For Intel TDX, this is [`TdxPolicy`].
    pub policy: u64,
    /// Compatibility mask.
    pub compatibility_mask: u32,
    /// Reserved, must be zero.
    pub reserved: u32,
}

/// The AMD SEV-SNP Guest policy used in [`IGVM_VHS_GUEST_POLICY::policy`].
///
/// For now, this matches the definition in Section 4.3 Guest Policy of the AMD
/// SEV-SNP specification.
#[bitfield(u64)]
#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct SnpPolicy {
    pub abi_minor: u8,
    pub abi_major: u8,
    #[bits(1)]
    pub smt: u8,
    #[bits(1)]
    pub reserved_must_be_one: u8,
    #[bits(1)]
    pub migrate_ma: u8,
    #[bits(1)]
    pub debug: u8,
    #[bits(1)]
    pub single_socket: u8,
    #[bits(43)]
    pub reserved: u64,
}

/// The Intel TDX policy used in [`IGVM_VHS_GUEST_POLICY::policy`].
#[bitfield(u64)]
#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct TdxPolicy {
    #[bits(1)]
    pub debug_allowed: u8,
    #[bits(1)]
    pub sept_ve_disable: u8,
    #[bits(62)]
    pub reserved: u64,
}

/// This region describes VTL2.
pub const IGVM_VHF_RELOCATABLE_REGION_IS_VTL2: u8 = 0x1;
/// RIP for the specified VP and VTL should be adjusted by the amount this
/// region was relocated.
pub const IGVM_VHF_RELOCATABLE_REGION_APPLY_RIP: u8 = 0x2;
/// GDTR for the specified VP and VTL should be adjusted by the amount this
/// region was relocated.
pub const IGVM_VHF_RELOCATABLE_REGION_APPLY_GDTR: u8 = 0x4;

/// Indicate a relocatable region. This region may be relocated according to the
/// fields within the header. The region must be relocated as a whole, with each
/// gpa within the region described being relocated by the same amount. Other
/// directive headers that specify gpas must be relocated by the amount the
/// region was relocated.
///
/// The loader must guarantee memory is present for the whole region described
/// by the header.
///
/// Additional flags specify behavior for registers and further information
/// about this region.
///
/// # Architecture
/// X64 only.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_RELOCATABLE_REGION {
    /// Compatibility mask.
    pub compatibility_mask: u32,
    /// VP Index for register flags to be applied to.
    pub vp_index: u16,
    /// VTL for register flags to be applied to.
    pub vtl: u8,
    /// Additional flags that describe this region.
    pub flags: u8,
    /// The relocation alignment this region can be relocated by.
    ///
    /// Must be multiple of 4K.
    pub relocation_alignment: u64,
    /// The base guest physical address of this relocatable region.
    ///
    /// `relocation_region_gpa` must be aligned to `relocation_alignment`.
    pub relocation_region_gpa: u64,
    /// The overall size of this relocatable region. Must be 4K aligned.
    pub relocation_region_size: u64,
    /// The minimum address this section can be relocated to.
    ///
    /// Must be aligned to `relocation_alignment`.
    pub minimum_relocation_gpa: u64,
    /// Maximum address this section can be relocated to.
    ///
    /// Must be aligned to `relocation_alignment`.
    pub maximum_relocation_gpa: u64,
}

/// Indicate the region of memory containing the page table which can be
/// relocated. This region must contain CR3. Page table pages that are described
/// that lay outside of this region will not be walked nor fixed up. Page tables
/// cannot lie within other relocatable regions. Similar to
/// [`IGVM_VHS_RELOCATABLE_REGION`], the loader must guarantee memory is present
/// for the whole region described by this header.
///
/// The VP index and VTL is used to describe the paging state for the page
/// table. CR3 will be then fixed up according to the amount this region was
/// relocated by. Other VPs within the same VTL that have the same initial CR3
/// value as the described VP will also be fixed up. There must be a
/// [`IGVM_VHS_VP_CONTEXT`] structure for the given vp index and vtl. The given
/// VP must be in 64 bit mode with paging enabled.
///
/// This region describes any additional pages the loader may use to allocate
/// additional entries to handle relocation. `used_size` represents the
/// allocated size starting from the base `gpa`.
///
/// The page table must map the address space as identity mapped, with VA = PA.
///
/// Initial page table data is specified by [`IGVM_VHS_PAGE_DATA`] headers that
/// are contained within the region described by this header. There must not be
/// any [`IGVM_VHS_PARAMETER_INSERT`] headers that refer to gpas described by
/// this header.
///
/// Page directory entries pointing to another page table are fixed up according
/// to the amount this region is relocated by, if the PDE points to a page
/// within this region.
///
/// Page table entries that map ranges that have been relocated are also further
/// fixed up. The entry must be moved to the new identity mapped VA
///     corresponding to where the region was relocated to.
///
/// For example:
/// - Region A is relocatable, and originally describes GPAs 0x1000 to 0x2000
/// - The page table contains a 1GB entry mapping 0x0 - 1GB.
/// - Region A is chosen to be relocated to a new base, 2GB.
/// - The page table entry previously identity mapping VA 0x0
/// - 1GB is now moved to 0x2GB - 0x3GB, which now identity maps 0x2GB - 0x3GB.
///
/// However, page table entries that map a larger range than the relocation
///     amount are not moved.
///
/// For example:
/// - Region A is relocatable, and originally describes GPAs 0x1000 to 0x2000
/// - The page table contains a 1GB entry mapping 0x0 - 1GB.
/// - Region A is chosen to be relocated to a new base, 0x5000.
/// - The page table entry previously identity mapping VA 0x0 - 1GB still maps
/// the relocated region, and is left as is mapping VA 0x0 - 1GB to PA 0x0 - 1GB.
///
/// For regions that are relocated at a non-aligned amount greater than the PTE
/// mapping size, the IGVM file is considered invalid.
///
/// For example:
/// - Region A is relocatable, and originally describes GPAs 0x0000 to 0x2000.
/// - The page table contains a 1GB entry mapping 0x0 - 1GB.
/// - Region A is chosen to be relocated to a new base, 1.5GB. This has a
/// relocation offset of +1.5GB.
/// - The page table entry previously identity mapping VA 0x0 - 1GB needs to be
/// relocated, but cannot be due to the the mapping now being unaligned. This
/// IGVM file is invalid, as the relocation region A has an incorrect
/// `relocation_alignment`.
///
/// Page table entries that map ranges that have not been relocated are left as
/// is.
///
/// # Architecture
/// X64 only.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_PAGE_TABLE_RELOCATION {
    /// Compatibility mask.
    pub compatibility_mask: u32,
    /// VP Index for paging information, like CR3 and EFER.
    pub vp_index: u16,
    /// VTL for paging information.
    pub vtl: u8,
    /// Reserved, must be zero.
    pub reserved: u8,
    /// The base of the page table region.
    pub gpa: u64,
    /// The total size in bytes of the page table region.
    pub size: u64,
    /// The number of already used pages by the pagetable.
    pub used_size: u64,
}

/// This structure defines a region of memory that can be used for holding
/// parameters to be passed into the guest. Parameter areas are created with
/// this structure, then parameters may be imported via parameter structures
/// that define the byte offset to deposit the given parameter into a given
/// parameter area by `parameter_area_index`.
///
/// The paramter area is imported into the guest address space via a
/// [`IGVM_VHS_PARAMETER_INSERT`] structure.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_PARAMETER_AREA {
    /// The size of the parameter region, in bytes. This must be page aligned.
    pub number_of_bytes: u64,
    /// An index that will be used by other structure types that refer to a
    /// parameter area. Each parameter area index can be used exactly once.
    pub parameter_area_index: u32,
    /// A file offset from which to load the initial contents of the parameter
    /// page; these initial contents can be overwritten as parameters are
    /// inserted according to other variable header structures which direct the
    /// insertion of parameters. If `file_offset` is zero, then the initial
    /// contents of the parameter page will be a page of zeroes.
    pub file_offset: u32,
}

/// Default memory state described by the IGVM_VHT_MEMORY_STATE_PARAMETER
/// parameter.
#[cfg(feature = "unstable")]
#[cfg_attr(docsrs, doc(cfg(feature = "unstable")))]
#[bitfield(u32)]
#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IgvmEnvironmentInfo {
    /// Default state of memory is not assigned to the guest (shared)
    pub memory_is_shared: bool,
    #[bits(31)]
    pub reserved: u32,
}

/// Page data types that describe the type of import for
/// [`IGVM_VHS_PAGE_DATA`].
#[open_enum]
#[derive(AsBytes, FromBytes, FromZeroes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IgvmPageDataType {
    /// Normal page data.
    NORMAL = 0x0,
    /// Secrets page.
    /// TODO: SEV-SNP only?
    SECRETS = 0x1,
    /// CPUID data
    /// TODO: SEV-SNP only?
    CPUID_DATA = 0x2,
    /// CPUID_XF
    /// SEV-SNP only?
    CPUID_XF = 0x3,
}

impl Default for IgvmPageDataType {
    fn default() -> Self {
        IgvmPageDataType::NORMAL
    }
}

/// Flags for [`IGVM_VHS_PAGE_DATA`] structures.
#[bitfield(u32)]
#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IgvmPageDataFlags {
    /// This page data is a 2MB page. If this is set, the
    /// [`IGVM_VHS_PAGE_DATA::gpa`] field must be aligned to 2MB.
    pub is_2mb_page: bool,
    /// This page data should be imported as unmeasured.
    pub unmeasured: bool,
    /// Reserved.
    #[bits(30)]
    pub reserved: u32,
}

/// This structure describes a page of data that should be loaded into the guest
/// address space.
///
/// The VTL permissions of page data loaded by the loader must conform to the
/// architectural default page permissions. On some platforms, this may require
/// the highest VTL to make pages loaded by the loader accessible to lower VTLs.
/// The following table describes architectural defaults for VTL permissions:
///
/// | Architecture              | VTL Access Permissions |
/// |---------------------------|------------------------|
/// | VBS                       | All VTLs               |
/// | SEV-SNP                   | Highest VTL only       |
/// | TDX partitioning disabled | All VTLs               |
/// | TDX partitioning enabled  | Highest VTL only       |
///
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_PAGE_DATA {
    /// The guest physical address at which this page data should be loaded; it
    /// must be aligned to a page size boundary.
    pub gpa: u64,
    /// The compatibility mask for this structure.
    pub compatibility_mask: u32,
    /// The FileOffset field specifies the offset in bytes at which the page
    /// data can be found. Note that this offset is relative to the beginning of
    /// the file, not the start of the file data section.
    ///
    /// If the file offset is zero, then a page of zeroes is to be loaded.  If
    /// the page contents are to be measured, and the underlying platform
    /// supports measured zero pages as a native page type, then the loader must
    /// request this page type; otherwise, the loader must generate a page of
    /// zeroes to load as the page contents.
    pub file_offset: u32,
    /// Flags.
    pub flags: IgvmPageDataFlags,
    /// The data type for this page data.
    pub data_type: IgvmPageDataType,
    /// Reserved.
    pub reserved: u16,
}

/// This structure controls the insertion of a parameter area into the guest
/// address space.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_PARAMETER_INSERT {
    /// The guest physical address where this parameter area should be imported
    /// into the guest address space. It must be page size aligned.
    ///
    /// Note that this parameter area is imported as a set of unmeasured pages
    /// when this structure is encountered by the loader, starting with the
    /// lowest GPA.
    pub gpa: u64,
    /// The compatibility mask for this structure.
    pub compatibility_mask: u32,
    /// The parameter area index that should be imported. This must have been
    /// declared by a previous [`IGVM_VHS_PARAMETER_AREA`] structure.
    ///
    /// Once a parameter area index is inserted, that index becomes invalid for
    /// future use.
    pub parameter_area_index: u32,
}

/// The common parameter structure used by different parameter types to indicate
/// to the loader which parameter area and what offset to deposit the specified
/// runtime info. See corresponding parameter types in
/// [`IgvmVariableHeaderType`].
///
/// A well behaving loader should fail loading the IGVM file if a parameter does
/// not fit in the requested parameter area with the specified offset.
///
/// However, because the values written are unmeasured and untrusted, isolated
/// guests must perform validation on the values written into parameter areas. A
/// malicious or buggy loader may write any values.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_PARAMETER {
    /// The paramter area index for this parameter.
    pub parameter_area_index: u32,
    /// The byte offset within the parameter area to deposit this parameter.
    pub byte_offset: u32,
}

/// This structure defines architecture specific that should be loaded into the
/// guest address space to represent an initial VP context.
///
/// If a file contains more than one [`IGVM_VHS_VP_CONTEXT`] entry, then each
/// VpIndex less than `n` must be used exactly once, where `n` is the number of
/// [`IGVM_VHS_VP_CONTEXT`] entries in the file.
///
/// For architectures such as Intel TDX that have an architectural reset state,
/// this structure is invalid.
///
/// Note that this structure is not aligned to 8 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_VP_CONTEXT {
    /// The guest physical address where the VP context data should be
    /// deposited, if required.
    ///
    /// For VBS, this must be zero. There is no VP context data to be deposited
    /// into the guest address space.
    ///
    /// For AMD SEV-SNP, this is the GPA to place the VMSA structure at.
    pub gpa: u64_le,
    /// The compatibility mask.
    pub compatibility_mask: u32,
    /// The file offset for arch specific VP context data.
    ///
    /// For VBS, the format of VP state is defined by a list of registers
    /// defined by [`VbsVpContextRegister`] structures prefixed by a
    /// [`VbsVpContextHeader`] in the file data section.
    ///
    /// For AMD SEV-SNP, the data is the form of the AMD SEV-SNP VMSA structure.
    pub file_offset: u32,
    /// The VP index for this VP context.
    pub vp_index: u16,
    /// Reserved.
    pub reserved: u16,
}

/// This structure describes a range in the GPA space of the guest that will be
/// reserved for reporting errors to the host. Therefore, the memory described
/// by this structure will also be marked as accessible by the host for the
/// lifetime of the VM.
///
/// These pages are imported by the loader with shared visibility.
///
/// The format of the data written by the guest into the error ranges to be read
/// by the host are outside of the scope of this specification.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_ERROR_RANGE {
    /// The guest physical address that this error range starts at. It must be
    /// page aligned.
    pub gpa: u64,
    /// Compatibility mask.
    pub compatibility_mask: u32,
    /// The size of this range in bytes. It must be page aligned.
    pub size_bytes: u32,
}

/// Format of VBS [`IGVM_VHS_VP_CONTEXT`] file data.
///
/// The format consists of a [`VbsVpContextHeader`] followed by a
/// `register_count` of [`VbsVpContextRegister`].
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct VbsVpContextHeader {
    /// The number of registers in this VP context.
    pub register_count: u32,
}

/// The registers associated with a VBS [`IGVM_VHS_VP_CONTEXT`] structure in the
/// file data section.
#[repr(C)]
#[derive(Clone, Copy, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct VbsVpContextRegister {
    /// The VTL to import this register to.
    pub vtl: u8,
    /// The Hyper-V register name as specified by the TLFS.
    pub register_name: u32_le,
    /// Padding to align up to next 0x10 offset.
    pub mbz: [u8; 11],
    /// The value of the register, as a Hyper-V register value.
    pub register_value: [u8; 16],
}

const_assert_eq!(size_of::<VbsVpContextRegister>(), 0x20);

/// This structure describes memory the IGVM file expects to be present in the
/// guest. This is a hint to the loader that the guest will not function without
/// memory present at the specified range, and should terminate the load process
/// if memory is not present.
///
/// This memory may or may not be measured, depending on the other structures
/// this range overlaps with in the variable header section.
///
/// Note that the guest cannot rely on memory being present at this location at
/// runtime, as a malicious host may choose to ignore this header.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_REQUIRED_MEMORY {
    /// The base guest physical address for this range. This must be page
    /// aligned.
    pub gpa: u64,
    /// Compatibility mask.
    pub compatibility_mask: u32,
    /// The number of bytes for this range. This must be page aligned.
    pub number_of_bytes: u32,
    /// Flags for this range, as defined by [`RequiredMemoryFlags`].
    pub flags: RequiredMemoryFlags,
    /// Reserved.
    pub reserved: u32,
}

/// Flags for [`IGVM_VHS_REQUIRED_MEMORY`].
#[bitfield(u32)]
#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct RequiredMemoryFlags {
    pub vtl2_protectable: bool,
    #[bits(31)]
    pub reserved: u32,
}

/// A structure describing memory via a range of pages.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_MEMORY_RANGE {
    /// The base guest physical page number for this range.
    pub starting_gpa_page_number: u64,
    /// The number of pages in this range.
    pub number_of_pages: u64,
}

/// The format used to describe the MMIO ranges of the guest for a
/// [`IgvmVariableHeaderType::IGVM_VHT_MMIO_RANGES`] parameter.
///
/// Note that this structure can only define two mmio ranges, for a full
/// reporting of the guest's mmio ranges, the
/// [`IgvmVariableHeaderType::IGVM_VHT_DEVICE_TREE`] parameter should be used
/// instead.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_MMIO_RANGES {
    /// The mmio ranges for the guest. Note that this structure can only report
    /// two ranges, regardless of how many are available to the guest.
    pub mmio_ranges: [IGVM_VHS_MEMORY_RANGE; 2],
}

/// Signature for SNP ID block. See the corresponding PSP definitions.
#[repr(C)]
#[derive(Clone, Copy, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_SNP_ID_BLOCK_SIGNATURE {
    /// r_comp
    pub r_comp: [u8; 72],
    /// s_comp
    pub s_comp: [u8; 72],
}

/// Public key for SNP ID block. See the corresponding PSP definitions.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY {
    /// curve
    pub curve: u32,
    /// Reserved.
    pub reserved: u32,
    /// qx
    pub qx: [u8; 72],
    /// qy
    pub qy: [u8; 72],
}

/// This structure describes the AMD SEV-SNP ID block.
///
/// AuthorKeyEnabled is set to 0x1 if an author key is to be used, with the
/// following corresponding author keys populated. Otherwise, the author key
/// fields must be zero.
///
/// Other fields share the same meaning as defined in the SNP API specification.
///
/// TODO: doc links for fields to SNP spec.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct IGVM_VHS_SNP_ID_BLOCK {
    /// Compatibility mask.
    pub compatibility_mask: u32,
    /// author_key_enabled
    pub author_key_enabled: u8,
    /// reserved
    pub reserved: [u8; 3],
    /// ld
    pub ld: [u8; 48],
    /// family id
    pub family_id: [u8; 16],
    /// image id
    pub image_id: [u8; 16],
    /// version
    pub version: u32,
    /// guest svm
    pub guest_svn: u32,
    /// id key algorithm
    pub id_key_algorithm: u32,
    /// author key algorithm
    pub author_key_algorithm: u32,
    /// id key signature
    pub id_key_signature: IGVM_VHS_SNP_ID_BLOCK_SIGNATURE,
    /// id public key
    pub id_public_key: IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY,
    /// author key signature
    pub author_key_signature: IGVM_VHS_SNP_ID_BLOCK_SIGNATURE,
    /// author public key
    pub author_public_key: IGVM_VHS_SNP_ID_BLOCK_PUBLIC_KEY,
}

/// This structure describes a VBS measurement to be used with Hyper-V's VBS
/// isolation architecture.
///
/// TODO: doc fields
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes)]
pub struct IGVM_VHS_VBS_MEASUREMENT {
    /// Compatibility mask
    pub compatibility_mask: u32,
    /// version
    pub version: u32,
    /// product id
    pub product_id: u32,
    /// module id
    pub module_id: u32,
    /// security version
    pub security_version: u32,
    /// policy flags
    pub policy_flags: u32,
    /// boot digest algo
    pub boot_digest_algo: u32,
    /// signing algo
    pub signing_algo: u32,
    /// boot measurement digest
    pub boot_measurement_digest: [u8; 64],
    /// signature
    pub signature: [u8; 256],
    /// public key
    pub public_key: [u8; 512],
}

/// The type of memory described by a memory map entry or device tree node.
#[open_enum]
#[derive(AsBytes, FromBytes, FromZeroes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MemoryMapEntryType {
    /// Normal memory.
    MEMORY = 0x0,
    /// Platform reserved memory.
    PLATFORM_RESERVED = 0x1,
    /// Persistent memory (PMEM).
    PERSISTENT = 0x2,
    /// Memory where VTL2 protections that deny access to lower VTLs can be
    /// applied. Some isolation architectures only allow VTL2 protections on
    /// certain memory ranges.
    VTL2_PROTECTABLE = 0x3,
}

impl Default for MemoryMapEntryType {
    fn default() -> Self {
        Self::MEMORY
    }
}

/// Flags associated with a memory map entry.
#[bitfield(u16)]
#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct MemoryMapEntryFlags {
    /// Memory is in the shared state, and an explicit call must be made to
    /// change it to the private state before it can be accepted and used.
    pub is_shared: bool,
    #[bits(15)]
    pub reserved: u16,
}

/// The structure deposited by the loader for memory map entries for
/// [`IgvmVariableHeaderType::IGVM_VHT_MEMORY_MAP`] that describe memory
/// available to the guest.
///
/// A well-behaved loader will report these in sorted order, with a final entry
/// with `number_of_pages` with zero signifying the last entry.
#[repr(C)]
#[derive(Copy, Clone, Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
pub struct IGVM_VHS_MEMORY_MAP_ENTRY {
    /// The starting gpa page number for this range of memory.
    pub starting_gpa_page_number: u64,
    /// The number of pages in this range of memory.
    pub number_of_pages: u64,
    /// The type of memory this entry represents.
    pub entry_type: MemoryMapEntryType,
    /// Flags about this memory entry.
    pub flags: MemoryMapEntryFlags,
    /// Reserved.
    pub reserved: u32,
}

/// The signature algorithm to use for VBS digest.
#[open_enum]
#[derive(AsBytes, FromBytes, FromZeroes, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VbsDigestAlgorithm {
    /// Invalid.
    INVALID = 0x0,
    /// SHA256.
    SHA256 = 0x1,
}

/// The signature algorithm to use for VBS measurement.
#[open_enum]
#[derive(AsBytes, FromBytes, FromZeroes, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum VbsSigningAlgorithm {
    /// Invalid.
    INVALID = 0x0,
    /// ECDSA P384.
    ECDSA_P384 = 0x1,
}
