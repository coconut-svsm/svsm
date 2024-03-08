// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Device tree (DT) specific information related to IGVM.

/// The property name to describe IGVM type specific information on a DT node.
///
/// A DT memory node is extended with the IGVM type property to describe the
/// IGVM memory type for that node. This is encoded as a u32 value containing
/// the type defined by [`crate::MemoryMapEntryType`].
pub const IGVM_DT_IGVM_TYPE_PROPERTY: &str = "microsoft,igvm-type";

/// The property name to describe IGVM specific flags on a DT node.
///
/// A DT memory node is extended with the IGVM flags property to describe the
/// IGVM memory flags for that node. This is encoded as a u32 value containing
/// the type defined by [`crate::MemoryMapEntryFlags`].
pub const IGVM_DT_IGVM_FLAGS_PROPERTY: &str = "microsoft,igvm-flags";

/// The property name to describe VTL specific information on a DT node.
///
/// A DT VMBUS root node is extended with the VTL property to describe the VTL
/// this root node is for. VTL is encoded as a u32 value.
pub const IGVM_DT_VTL_PROPERTY: &str = "microsoft,vtl";
