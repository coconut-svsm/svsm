// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Coconut-SVSM Authors
//
// Author: Carlos López <carlos.lopezr4096@gmail.com>

use super::{MappingRead, MappingWrite, OwnedMapping};
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::error::SvsmError;
use crate::mm::memory::valid_phys_region;
use core::arch::asm;
use zerocopy::{FromBytes, IntoBytes};

/// An empty structure to indicate access to guest-shared memory.
#[derive(Debug, Clone, Copy)]
pub struct Guest;

impl MappingRead for Guest {
    unsafe fn read<T: FromBytes>(
        src: *const T,
        dst: *mut T,
        count: usize,
    ) -> Result<(), SvsmError> {
        // TODO: optimize this to a single call
        for i in 0..count {
            // SAFETY: safety requirements must be upheld by the caller
            unsafe {
                do_movsb(src.add(i), dst.add(i))?;
            }
        }
        Ok(())
    }
}

impl MappingWrite for Guest {
    unsafe fn write<T: IntoBytes>(
        src: *const T,
        dst: *mut T,
        count: usize,
    ) -> Result<(), SvsmError> {
        // TODO: optimize this
        for i in 0..count {
            // SAFETY: safety requirements must be upheld by the caller
            unsafe {
                do_movsb(src.add(i), dst.add(i))?;
            }
        }
        Ok(())
    }

    unsafe fn write_bytes<T: IntoBytes>(_: *mut T, _: usize, _: u8) -> Result<(), SvsmError> {
        unimplemented!()
    }
}

impl<T> OwnedMapping<Guest, T> {
    /// Maps the given physical address of guest memory. This method is safe
    /// because it checks that the mapped region belongs to the guest.
    ///
    /// # Errors
    ///
    /// Other than due to allocation failures or page table mainupulation
    /// errors, this function may fail if the provided physical address is not
    /// present in the guest's memory map.
    pub fn map_guest(paddr: PhysAddr) -> Result<Self, SvsmError> {
        if !valid_phys_region(&Self::phys_region(paddr, 1)?) {
            return Err(SvsmError::Mem);
        }
        Self::map::<false>(paddr)
    }

    /// Maps the given physical address of guest memory as a slice with a
    /// dynamic size. This method is safe because it checks that the mapped
    /// region belongs to the guest.
    ///
    /// # Errors
    ///
    /// Other than due to allocation failures or page table mainupulation
    /// errors, this function may fail if the provided physical address is not
    /// present in the guest's memory map.
    pub fn map_guest_slice(
        paddr: PhysAddr,
        len: usize,
    ) -> Result<OwnedMapping<Guest, [T]>, SvsmError> {
        if !valid_phys_region(&Self::phys_region(paddr, len)?) {
            return Err(SvsmError::Mem);
        }
        Self::map_slice::<false>(paddr, len)
    }
}

/// Read one byte from a virtual address.
///
/// # Arguments
///
/// - `v` - Virtual address to read.
///
/// # Returns
///
/// `Ok(u8)` with the value read on success, `Err(SvsmError)` on failure.
///
/// # Safety
///
/// Any safety requirements for accessing raw pointers apply here as well.
#[inline]
pub unsafe fn read_u8(v: VirtAddr) -> Result<u8, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

    // SAFETY: Assembly dereferences the pointer, which is safe when the
    // function's safety requirements are fulfilled.
    unsafe {
        asm!("1: movb ({0}), %al",
             "   xorq %rcx, %rcx",
             "2:",
             ".pushsection \"__exception_table\",\"a\"",
             ".balign 16",
             ".quad (1b)",
             ".quad (2b)",
             ".popsection",
                in(reg) v.bits(),
                out("rax") val,
                out("rcx") rcx,
                options(att_syntax, nostack));
    }

    let ret: u8 = (val & 0xff) as u8;
    if rcx == 0 {
        Ok(ret)
    } else {
        Err(SvsmError::Fault)
    }
}

/// Writes one byte at a virtual address.
///
/// # Safety
///
/// The caller must verify not to corrupt arbitrary memory, as this function
/// doesn't make any checks in that regard.
///
/// # Returns
///
/// Returns an error if the specified address is not mapped or is not mapped
/// with the appropriate write permissions.
#[inline]
pub unsafe fn write_u8(v: VirtAddr, val: u8) -> Result<(), SvsmError> {
    let mut rcx: u64;

    // SAFETY: Assembly writes to virtual address, safe when function's safety
    // requirements are fulfilled.
    unsafe {
        asm!("1: movb %al, ({0})",
             "   xorq %rcx, %rcx",
             "2:",
             ".pushsection \"__exception_table\",\"a\"",
             ".balign 16",
             ".quad (1b)",
             ".quad (2b)",
             ".popsection",
                in(reg) v.bits(),
                in("rax") val as u64,
                out("rcx") rcx,
                options(att_syntax, nostack));
    }

    if rcx == 0 {
        Ok(())
    } else {
        Err(SvsmError::Fault)
    }
}

/// Read one word from a virtual address.
///
/// # Arguments
///
/// - `v` - Virtual address to read.
///
/// # Returns
///
/// `Ok(u16)` with the value read on success, `Err(SvsmError)` on failure.
///
/// # Safety
///
/// Any safety requirements for accessing raw pointers apply here as well.
#[expect(dead_code)]
#[inline]
unsafe fn read_u16(v: VirtAddr) -> Result<u16, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

    // SAFETY: Assembly dereferences the pointer, which is safe when the
    // function's safety requirements are fulfilled.
    unsafe {
        asm!("1: movw ({0}), {1}",
             "   xorq %rcx, %rcx",
             "2:",
             ".pushsection \"__exception_table\",\"a\"",
             ".balign 16",
             ".quad (1b)",
             ".quad (2b)",
             ".popsection",
                in(reg) v.bits(),
                out(reg) val,
                out("rcx") rcx,
                options(att_syntax, nostack));
    }

    let ret: u16 = (val & 0xffff) as u16;
    if rcx == 0 {
        Ok(ret)
    } else {
        Err(SvsmError::Fault)
    }
}

/// Read one dword from a virtual address.
///
/// # Arguments
///
/// - `v` - Virtual address to read.
///
/// # Returns
///
/// `Ok(u32)` with the value read on success, `Err(SvsmError)` on failure.
///
/// # Safety
///
/// Any safety requirements for accessing raw pointers apply here as well.
#[expect(dead_code)]
#[inline]
unsafe fn read_u32(v: VirtAddr) -> Result<u32, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

    // SAFETY: Assembly dereferences the pointer, which is safe when the
    // function's safety requirements are fulfilled.
    unsafe {
        asm!("1: movl ({0}), {1}",
             "   xorq %rcx, %rcx",
             "2:",
             ".pushsection \"__exception_table\",\"a\"",
             ".balign 16",
             ".quad (1b)",
             ".quad (2b)",
             ".popsection",
                in(reg) v.bits(),
                out(reg) val,
                out("rcx") rcx,
                options(att_syntax, nostack));
    }

    let ret: u32 = (val & 0xffffffff) as u32;
    if rcx == 0 {
        Ok(ret)
    } else {
        Err(SvsmError::Fault)
    }
}

/// Read one qword from a virtual address.
///
/// # Arguments
///
/// - `v` - Virtual address to read.
///
/// # Returns
///
/// `Ok(u32)` with the value read on success, `Err(SvsmError)` on failure.
///
/// # Safety
///
/// Any safety requirements for accessing raw pointers apply here as well.
#[expect(dead_code)]
#[inline]
unsafe fn read_u64(v: VirtAddr) -> Result<u64, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

    // SAFETY: Assembly dereferences the pointer, which is safe when the
    // function's safety requirements are fulfilled.
    unsafe {
        asm!("1: movq ({0}), {1}",
             "   xorq %rcx, %rcx",
             "2:",
             ".pushsection \"__exception_table\",\"a\"",
             ".balign 16",
             ".quad (1b)",
             ".quad (2b)",
             ".popsection",
                in(reg) v.bits(),
                out(reg) val,
                out("rcx") rcx,
                options(att_syntax, nostack));
    }
    if rcx == 0 {
        Ok(val)
    } else {
        Err(SvsmError::Fault)
    }
}

/// Copies `size` number of bytes from `src` to `dst`, catching any fault that
/// might happen during the operation.
///
/// # Safety
///
/// The caller must make sure that writing to `dst` does not harm memory safety.
#[inline]
unsafe fn copy_bytes(src: *const u8, dst: *mut u8, size: usize) -> Result<(), SvsmError> {
    let mut rcx: u64;

    // SAFETY: Safe as long as the function's safety requirements are met. Any
    // fault that might happen is handled via the exception handlers.
    unsafe {
        asm!("1:cld
                rep movsb
              2:
             .pushsection \"__exception_table\",\"a\"
             .balign 16
             .quad (1b)
             .quad (2b)
             .popsection",
                inout("rsi") src.expose_provenance() => _,
                inout("rdi") dst.expose_provenance() => _,
                inout("rcx") size => rcx,
                options(att_syntax, nostack));
    }

    if rcx == 0 {
        Ok(())
    } else {
        Err(SvsmError::Fault)
    }
}

/// Copies `src` to `dst`.
///
/// # Safety
///
/// The caller must make sure that writing to `dst` does not harm memory safety.
#[inline]
pub(super) unsafe fn do_movsb<T>(src: *const T, dst: *mut T) -> Result<(), SvsmError> {
    let size: usize = size_of::<T>();

    // SAFETY: Only safe when safety requirements for do_movsb() are fulfilled.
    unsafe { copy_bytes(src.cast(), dst.cast(), size) }
}

#[cfg(test)]
mod tests {
    use crate::mm::access::{BorrowedMapping, ReadableMapping};

    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    fn test_read_u8_valid_address() {
        // Create a region to read from
        let test_buffer: [u8; 6] = [0; 6];
        let test_address = VirtAddr::from(test_buffer.as_ptr());

        // SAFETY: The address is mapped and can be safely accessed.
        let result = unsafe { read_u8(test_address).unwrap() };

        assert_eq!(result, test_buffer[0]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    fn test_write_u8_valid_address() {
        // Create a mutable region we can write into
        let mut test_buffer: [u8; 6] = [0; 6];
        let test_address = VirtAddr::from(test_buffer.as_mut_ptr());
        let data_to_write = 0x42;

        // SAFETY: test_address points to the virtual address of test_buffer.
        unsafe {
            write_u8(test_address, data_to_write).unwrap();
        }

        assert_eq!(test_buffer[0], data_to_write);
    }

    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    fn test_read_15_bytes_valid_address() {
        let test_buffer = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let test_addr = VirtAddr::from(test_buffer.as_ptr());
        // SAFETY: we can treat the local stack as guest memory for testing
        // purposes.
        let ptr = unsafe { BorrowedMapping::<Guest, [u8; 15]>::from_address(test_addr).unwrap() };
        let result = ptr.read().unwrap();

        assert_eq!(result, test_buffer);
    }

    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_read_invalid_address() {
        // SAFETY: we are not aliasing memory in an invalid way. The address is invalid but
        // the Guest access should catch it.
        let ptr =
            unsafe { BorrowedMapping::<Guest, u8>::from_address(0xDEAD_BEEFusize.into()).unwrap() };
        let err = ptr.read();
        assert!(err.is_err());
    }
}
