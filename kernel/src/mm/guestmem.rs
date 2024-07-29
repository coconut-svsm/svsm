// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
use crate::error::SvsmError;
use crate::insn_decode::{InsnError, InsnMachineMem};
use core::arch::asm;
use core::mem::{size_of, MaybeUninit};

#[allow(dead_code)]
#[inline]
pub fn read_u8(v: VirtAddr) -> Result<u8, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

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
        Err(SvsmError::InvalidAddress)
    }
}

/// Writes 1 byte at a virtual address.
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
#[allow(dead_code)]
#[inline]
pub unsafe fn write_u8(v: VirtAddr, val: u8) -> Result<(), SvsmError> {
    let mut rcx: u64;

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
        Err(SvsmError::InvalidAddress)
    }
}

#[allow(dead_code)]
#[inline]
unsafe fn read_u16(v: VirtAddr) -> Result<u16, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

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

    let ret: u16 = (val & 0xffff) as u16;
    if rcx == 0 {
        Ok(ret)
    } else {
        Err(SvsmError::InvalidAddress)
    }
}

#[allow(dead_code)]
#[inline]
unsafe fn read_u32(v: VirtAddr) -> Result<u32, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

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

    let ret: u32 = (val & 0xffffffff) as u32;
    if rcx == 0 {
        Ok(ret)
    } else {
        Err(SvsmError::InvalidAddress)
    }
}

#[allow(dead_code)]
#[inline]
unsafe fn read_u64(v: VirtAddr) -> Result<u64, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

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

    if rcx == 0 {
        Ok(val)
    } else {
        Err(SvsmError::InvalidAddress)
    }
}

#[inline]
unsafe fn do_movsb<T>(src: *const T, dst: *mut T) -> Result<(), SvsmError> {
    let size: usize = size_of::<T>();
    let mut rcx: u64;

    asm!("1:cld
            rep movsb
          2:
         .pushsection \"__exception_table\",\"a\"
         .balign 16
         .quad (1b)
         .quad (2b)
         .popsection",
            inout("rsi") src => _,
            inout("rdi") dst => _,
            inout("rcx") size => rcx,
            options(att_syntax, nostack));

    if rcx == 0 {
        Ok(())
    } else {
        Err(SvsmError::InvalidAddress)
    }
}

#[derive(Debug)]
pub struct GuestPtr<T: Copy> {
    ptr: *mut T,
}

impl<T: Copy> GuestPtr<T> {
    #[inline]
    pub fn new(v: VirtAddr) -> Self {
        Self {
            ptr: v.as_mut_ptr::<T>(),
        }
    }

    #[inline]
    pub const fn from_ptr(p: *mut T) -> Self {
        Self { ptr: p }
    }

    /// # Safety
    ///
    /// The caller must verify not to read arbitrary memory, as this function
    /// doesn't make any checks in that regard.
    ///
    /// # Returns
    ///
    /// Returns an error if the specified address is not mapped.
    #[inline]
    pub unsafe fn read(&self) -> Result<T, SvsmError> {
        let mut buf = MaybeUninit::<T>::uninit();

        unsafe {
            do_movsb(self.ptr, buf.as_mut_ptr())?;
            Ok(buf.assume_init())
        }
    }

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
    pub unsafe fn write(&self, buf: T) -> Result<(), SvsmError> {
        unsafe { do_movsb(&buf, self.ptr) }
    }

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
    pub unsafe fn write_ref(&self, buf: &T) -> Result<(), SvsmError> {
        unsafe { do_movsb(buf, self.ptr) }
    }

    #[inline]
    pub const fn cast<N: Copy>(&self) -> GuestPtr<N> {
        GuestPtr::from_ptr(self.ptr.cast())
    }

    #[inline]
    pub fn offset(&self, count: isize) -> Self {
        GuestPtr::from_ptr(self.ptr.wrapping_offset(count))
    }
}

impl<T: Copy> InsnMachineMem for GuestPtr<T> {
    type Item = T;

    /// Safety: See the GuestPtr's read() method documentation for safety requirements.
    unsafe fn mem_read(&self) -> Result<Self::Item, InsnError> {
        self.read().map_err(|_| InsnError::MemRead)
    }

    /// Safety: See the GuestPtr's write() method documentation for safety requirements.
    unsafe fn mem_write(&mut self, data: Self::Item) -> Result<(), InsnError> {
        self.write(data).map_err(|_| InsnError::MemWrite)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    fn test_read_u8_valid_address() {
        // Create a region to read from
        let test_buffer: [u8; 6] = [0; 6];
        let test_address = VirtAddr::from(test_buffer.as_ptr());

        let result = read_u8(test_address).unwrap();

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
        let ptr: GuestPtr<[u8; 15]> = GuestPtr::new(test_addr);
        // SAFETY: ptr points to test_buffer's virtual address
        let result = unsafe { ptr.read().unwrap() };

        assert_eq!(result, test_buffer);
    }

    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_read_invalid_address() {
        let ptr: GuestPtr<u8> = GuestPtr::new(VirtAddr::new(0xDEAD_BEEF));
        // SAFETY: ptr points to an invalid virtual address (0xDEADBEEF is
        // unmapped). ptr.read() will return an error but this is expected.
        let err = unsafe { ptr.read() };
        assert!(err.is_err());
    }
}
