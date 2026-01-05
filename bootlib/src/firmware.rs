// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

use uuid::{Uuid, uuid};

pub const OVMF_RESET_VECTOR_GUID: Uuid = uuid!("813d7b2c-9558-4d88-8b31-1427a85abe69");
pub const OVMF_SEV_METADATA_GUID: Uuid = uuid!("dc886566-984a-4798-a75e-5585a7bf67cc");
pub const OVMF_TDX_METADATA_GUID: Uuid = uuid!("e47a6535-984a-4798-865e-4685a7bf8ec2");
pub const OVMF_IGVM_METADATA_GUID: Uuid = uuid!("784fa70e-3176-4677-8a20-04b68699e374");
pub const OVMF_TABLE_FOOTER_GUID: Uuid = uuid!("96b582de-1fb2-45f7-baea-a366c55a082d");
pub const SEV_INFO_BLOCK_GUID: Uuid = uuid!("00f771de-1a7e-4fcb-890e-68c77e2fb44e");
pub const SVSM_INFO_GUID: Uuid = uuid!("a789a612-0597-4c4b-a49f-cbb1fe9d1ddd");

pub const SEV_META_DESC_TYPE_MEM: u32 = 1;
pub const SEV_META_DESC_TYPE_SECRETS: u32 = 2;
pub const SEV_META_DESC_TYPE_CPUID: u32 = 3;
pub const SEV_META_DESC_TYPE_CAA: u32 = 4;
pub const SEV_META_DESC_TYPE_KERNEL_HASHES: u32 = 16;

pub const IGVM_META_DESC_TYPE_PARAM_AREA: u32 = 0x100;
pub const IGVM_META_DESC_TYPE_MEMORY_MAP: u32 = 0x101;
pub const IGVM_META_DESC_TYPE_HOB_AREA: u32 = 0x200;
