// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) Microsoft Corporation
//
// Author: Jon Lange (jlange@microsoft.com)

use bitfield_struct::bitfield;

pub const APIC_REGISTER_APIC_ID: u64 = 0x802;
pub const APIC_REGISTER_TPR: u64 = 0x808;
pub const APIC_REGISTER_PPR: u64 = 0x80A;
pub const APIC_REGISTER_EOI: u64 = 0x80B;
pub const APIC_REGISTER_ISR_0: u64 = 0x810;
pub const APIC_REGISTER_ISR_7: u64 = 0x817;
pub const APIC_REGISTER_TMR_0: u64 = 0x818;
pub const APIC_REGISTER_TMR_7: u64 = 0x81F;
pub const APIC_REGISTER_IRR_0: u64 = 0x820;
pub const APIC_REGISTER_IRR_7: u64 = 0x827;
pub const APIC_REGISTER_ICR: u64 = 0x830;
pub const APIC_REGISTER_SELF_IPI: u64 = 0x83F;

#[derive(Debug, PartialEq)]
pub enum IcrDestFmt {
    Dest = 0,
    OnlySelf = 1,
    AllWithSelf = 2,
    AllButSelf = 3,
}

impl IcrDestFmt {
    const fn into_bits(self) -> u64 {
        self as _
    }
    const fn from_bits(value: u64) -> Self {
        match value {
            3 => Self::AllButSelf,
            2 => Self::AllWithSelf,
            1 => Self::OnlySelf,
            _ => Self::Dest,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum IcrMessageType {
    Fixed = 0,
    Unknown = 3,
    Nmi = 4,
    Init = 5,
    Sipi = 6,
    ExtInt = 7,
}

impl IcrMessageType {
    const fn into_bits(self) -> u64 {
        self as _
    }
    const fn from_bits(value: u64) -> Self {
        match value {
            7 => Self::ExtInt,
            6 => Self::Sipi,
            5 => Self::Init,
            4 => Self::Nmi,
            0 => Self::Fixed,
            _ => Self::Unknown,
        }
    }
}

#[bitfield(u64)]
pub struct ApicIcr {
    pub vector: u8,
    #[bits(3)]
    pub message_type: IcrMessageType,
    pub destination_mode: bool,
    pub delivery_status: bool,
    rsvd_13: bool,
    pub assert: bool,
    pub trigger_mode: bool,
    #[bits(2)]
    pub remote_read_status: usize,
    #[bits(2)]
    pub destination_shorthand: IcrDestFmt,
    #[bits(12)]
    rsvd_31_20: u64,
    pub destination: u32,
}
