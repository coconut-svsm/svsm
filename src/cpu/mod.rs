// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

pub mod control_regs;
pub mod cpuid;
pub mod efer;
pub mod extable;
pub mod features;
pub mod gdt;
pub mod idt;
pub mod msr;
pub mod percpu;
pub mod smp;
pub mod tlb;
pub mod tss;
pub mod vc;
pub mod vmsa;

pub use idt::X86Regs;
pub use tlb::*;
