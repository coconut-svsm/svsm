// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::gdt::GDTEntry;
use crate::address::VirtAddr;
use core::arch::asm;
use core::num::NonZeroU8;
use core::ptr::addr_of;

// IST offsets
pub const IST_DF: NonZeroU8 = NonZeroU8::new(1).unwrap();

#[derive(Debug, Default, Clone, Copy)]
#[repr(C, packed(4))]
pub struct X86Tss {
    reserved0: u32,
    stacks: [VirtAddr; 3],
    reserved1: u64,
    ist_stacks: [VirtAddr; 7],
    reserved2: u64,
    reserved3: u16,
    io_bmp_base: u16,
}

pub const TSS_LIMIT: u64 = core::mem::size_of::<X86Tss>() as u64;

impl X86Tss {
    pub const fn new() -> Self {
        X86Tss {
            reserved0: 0,
            stacks: [VirtAddr::null(); 3],
            reserved1: 0,
            ist_stacks: [VirtAddr::null(); 7],
            reserved2: 0,
            reserved3: 0,
            io_bmp_base: (TSS_LIMIT + 1) as u16,
        }
    }

    /// # Safety
    /// No checks are performed on the stack address.  The caller must
    /// ensure that the address is valid for stack usage.
    pub unsafe fn set_ist_stack(&self, index: NonZeroU8, addr: VirtAddr) {
        // IST entries start at index 1
        let index = usize::from(index.get() - 1);
        let stack_ptr = addr_of!(self.ist_stacks[index]);
        // SAFETY: this move must be done in assembly because the target
        // address is unaligned, and is not a candidate for using `Cell` to
        // provide interior mutability on the stack pointer.
        unsafe {
            asm!("movq {0}, ({1})",
                 in(reg) u64::from(addr),
                 in(reg) stack_ptr,
                 options(att_syntax));
        }
    }

    /// # Safety
    /// No checks are performed on the stack address.  The caller must
    /// ensure that the address is valid for stack usage.
    pub unsafe fn set_rsp0(&self, addr: VirtAddr) {
        let stack_ptr = addr_of!(self.stacks[0]);
        // SAFETY: this move must be done in assembly because the target
        // address is unaligned, and is not a candidate for using `Cell` to
        // provide interior mutability on the stack pointer.
        unsafe {
            asm!("movq {0}, ({1})",
                 in(reg) u64::from(addr),
                 in(reg) stack_ptr,
                 options(att_syntax));
        }
    }

    pub fn to_gdt_entry(&self) -> (GDTEntry, GDTEntry) {
        let addr = (self as *const X86Tss) as u64;

        let mut desc0: u64 = 0;
        let mut desc1: u64 = 0;

        // Limit
        desc0 |= TSS_LIMIT & 0xffffu64;
        desc0 |= ((TSS_LIMIT >> 16) & 0xfu64) << 48;

        // Address
        desc0 |= (addr & 0x00ff_ffffu64) << 16;
        desc0 |= (addr & 0xff00_0000u64) << 32;
        desc1 |= addr >> 32;

        // Present
        desc0 |= 1u64 << 47;

        // Type
        desc0 |= 0x9u64 << 40;

        (GDTEntry::from_raw(desc0), GDTEntry::from_raw(desc1))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::mem::offset_of;

    #[test]
    fn test_tss_offsets() {
        assert_eq!(offset_of!(X86Tss, reserved0), 0x0);
        assert_eq!(offset_of!(X86Tss, stacks), 0x4);
        assert_eq!(offset_of!(X86Tss, reserved1), 0x1c);
        assert_eq!(offset_of!(X86Tss, ist_stacks), 0x24);
        assert_eq!(offset_of!(X86Tss, reserved2), 0x5c);
        assert_eq!(offset_of!(X86Tss, reserved3), 0x64);
        assert_eq!(offset_of!(X86Tss, io_bmp_base), 0x66);
    }
}
