// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

pub mod apic;
pub mod control_regs;
pub mod cpuid;
pub mod efer;
pub mod extable;
pub mod features;
pub mod gdt;
pub mod idt;
pub mod irq_state;
pub mod mem;
pub mod msr;
pub mod percpu;
pub mod registers;
pub mod smp;
pub mod tlb;
pub mod tss;
pub mod vc;
pub mod vmsa;

pub use apic::LocalApic;
pub use gdt::{gdt, gdt_mut};
pub use idt::common::X86ExceptionContext;
pub use irq_state::{irqs_disabled, irqs_enabled, IrqGuard, IrqState};
pub use percpu::{irq_nesting_count, irqs_disable, irqs_enable};
pub use registers::{X86GeneralRegs, X86InterruptFrame, X86SegmentRegs};
pub use tlb::*;
