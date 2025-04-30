// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2025 Intel Corporation
//
// Author: Peter Fang <peter.fang@intel.com>

use crate::cpu::apic::{ApicIcr, IcrDestFmt, IcrMessageType};
use crate::cpu::msr::{read_msr, write_msr};
use crate::cpu::percpu::this_cpu;
use crate::cpu::x86::apic::{
    APIC_OFFSET_ICR, APIC_OFFSET_ID, APIC_OFFSET_SELF_IPI, APIC_OFFSET_SPIV,
};
use crate::cpu::x86::x2apic::{MSR_X2APIC_BASE, MSR_X2APIC_SELF_IPI};
use crate::cpu::x86::{ApicAccess, MSR_APIC_BASE};
use crate::tdx::tdcall;

#[derive(Debug)]
pub struct TdxApicAccessor {}

impl TdxApicAccessor {
    fn is_self_ipi(offset: usize, value: u64) -> Option<u64> {
        match offset {
            // Preserve hw behaviors (e.g. reserved-bit checking)
            APIC_OFFSET_SELF_IPI => Some(value),
            // Convert to a self-IPI if applicable
            APIC_OFFSET_ICR => {
                let icr = ApicIcr::from(value);
                match icr.destination_shorthand() {
                    // Logical destination mode can be supported if needed;
                    // defer to GHCI for now.
                    // The same goes for lowest priority delivery mode.
                    IcrDestFmt::Dest => {
                        if icr.message_type() == IcrMessageType::Fixed
                            && !icr.destination_mode()
                            && icr.destination() == this_cpu().get_apic_id()
                        {
                            Some(icr.vector() as u64)
                        } else {
                            None
                        }
                    }
                    IcrDestFmt::OnlySelf => {
                        debug_assert!(icr.message_type() == IcrMessageType::Fixed);
                        Some(icr.vector() as u64)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    // NOTE:
    // Needs to be updated when new GHCI APIC registers are used.
    fn is_ghci_msr(offset: usize) -> bool {
        matches!(offset, APIC_OFFSET_ID | APIC_OFFSET_SPIV | APIC_OFFSET_ICR)
    }
}

impl ApicAccess for TdxApicAccessor {
    fn update_apic_base(&self, and_mask: u64, or_mask: u64) {
        let current_value = tdcall::tdvmcall_rdmsr(MSR_APIC_BASE);
        let new_value = (current_value & and_mask) | or_mask;

        if current_value != new_value {
            tdcall::tdvmcall_wrmsr(MSR_APIC_BASE, new_value);
        }
    }

    fn apic_write(&self, offset: usize, value: u64) {
        let msr = MSR_X2APIC_BASE + u32::try_from(offset).unwrap();

        if let Some(v) = Self::is_self_ipi(offset, value) {
            // SAFETY: Writes to X2APIC MSRs never harm memory safety.
            unsafe { write_msr(MSR_X2APIC_SELF_IPI, v) };
        } else if Self::is_ghci_msr(offset) {
            tdcall::tdvmcall_wrmsr(msr, value);
        } else {
            // SAFETY: Writes to X2APIC MSRs never harm memory safety.
            unsafe { write_msr(msr, value) };
        }
    }

    fn apic_read(&self, offset: usize) -> u64 {
        let msr = MSR_X2APIC_BASE + u32::try_from(offset).unwrap();

        if Self::is_ghci_msr(offset) {
            tdcall::tdvmcall_rdmsr(msr)
        } else {
            read_msr(msr)
        }
    }
}

pub static TDX_APIC_ACCESSOR: TdxApicAccessor = TdxApicAccessor {};
