pub mod control_regs;
pub mod features;
pub mod cpuid;
pub mod efer;
pub mod msr;
pub mod gdt;
pub mod idt;

#[cfg(feature = "slab")]
pub mod percpu;
