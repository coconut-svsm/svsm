// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

extern crate alloc;

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::x86::smap::{clac, stac};
use crate::error::SvsmError;
use crate::insn_decode::{InsnError, InsnMachineMem};
use crate::mm::{
    memory::valid_phys_region, ptguards::PerCPUPageMappingGuard, USER_MEM_END, USER_MEM_START,
};
use crate::utils::MemoryRegion;
use alloc::string::String;
use alloc::vec::Vec;
use core::arch::asm;
use core::ffi::c_char;
use core::mem::{size_of, MaybeUninit};
use syscall::PATH_MAX;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

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
        Err(SvsmError::Fault)
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
        Err(SvsmError::Fault)
    }
}

#[expect(dead_code)]
#[inline]
unsafe fn read_u16(v: VirtAddr) -> Result<u16, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

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

#[expect(dead_code)]
#[inline]
unsafe fn read_u32(v: VirtAddr) -> Result<u32, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

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

#[expect(dead_code)]
#[inline]
unsafe fn read_u64(v: VirtAddr) -> Result<u64, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

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

#[inline]
unsafe fn copy_bytes(src: usize, dst: usize, size: usize) -> Result<(), SvsmError> {
    let mut rcx: u64;

    unsafe {
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
    }

    if rcx == 0 {
        Ok(())
    } else {
        Err(SvsmError::Fault)
    }
}

#[inline]
unsafe fn do_movsb<T>(src: *const T, dst: *mut T) -> Result<(), SvsmError> {
    let size: usize = size_of::<T>();
    let s = src as usize;
    let d = dst as usize;

    // SAFETY: Only safe when safety requirements for do_movsb() are fulfilled.
    unsafe { copy_bytes(s, d, size) }
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
        unsafe { self.read().map_err(|_| InsnError::MemRead) }
    }

    /// Safety: See the GuestPtr's write() method documentation for safety requirements.
    unsafe fn mem_write(&mut self, data: Self::Item) -> Result<(), InsnError> {
        unsafe { self.write(data).map_err(|_| InsnError::MemWrite) }
    }
}

struct UserAccessGuard;

impl UserAccessGuard {
    pub fn new() -> Self {
        stac();
        Self
    }
}

impl Drop for UserAccessGuard {
    fn drop(&mut self) {
        clac();
    }
}

#[derive(Debug)]
pub struct UserPtr<T: Copy> {
    guest_ptr: GuestPtr<T>,
}

impl<T: Copy> UserPtr<T> {
    #[inline]
    pub fn new(v: VirtAddr) -> Self {
        Self {
            guest_ptr: GuestPtr::new(v),
        }
    }

    fn check_bounds(&self) -> bool {
        let v = VirtAddr::from(self.guest_ptr.ptr);

        (USER_MEM_START..USER_MEM_END).contains(&v)
            && (USER_MEM_START..USER_MEM_END).contains(&(v + size_of::<T>()))
    }

    #[inline]
    pub fn read(&self) -> Result<T, SvsmError>
    where
        T: FromBytes,
    {
        if !self.check_bounds() {
            return Err(SvsmError::InvalidAddress);
        }
        let _guard = UserAccessGuard::new();
        unsafe { self.guest_ptr.read() }
    }

    #[inline]
    pub fn write(&self, buf: T) -> Result<(), SvsmError> {
        self.write_ref(&buf)
    }

    #[inline]
    pub fn write_ref(&self, buf: &T) -> Result<(), SvsmError> {
        if !self.check_bounds() {
            return Err(SvsmError::InvalidAddress);
        }
        let _guard = UserAccessGuard::new();
        unsafe { self.guest_ptr.write_ref(buf) }
    }

    #[inline]
    pub const fn cast<N: Copy>(&self) -> UserPtr<N> {
        UserPtr {
            guest_ptr: self.guest_ptr.cast(),
        }
    }

    #[inline]
    pub fn offset(&self, count: isize) -> UserPtr<T> {
        UserPtr {
            guest_ptr: self.guest_ptr.offset(count),
        }
    }
}

impl UserPtr<c_char> {
    /// Reads a null-terminated C string from the user space.
    /// Allocates memory for the string and returns a `String`.
    pub fn read_c_string(&self) -> Result<String, SvsmError> {
        let mut buffer = Vec::new();

        for offset in 0..PATH_MAX {
            let current_ptr = self.offset(offset as isize);
            let char_result = current_ptr.read()?;
            match char_result {
                0 => return String::from_utf8(buffer).map_err(|_| SvsmError::InvalidUtf8),
                c => buffer.push(c as u8),
            }
        }
        Err(SvsmError::InvalidBytes)
    }
}

fn check_bounds_user(start: usize, len: usize) -> Result<(), SvsmError> {
    let end: usize = start.checked_add(len).ok_or(SvsmError::InvalidAddress)?;

    if end > USER_MEM_END.bits() {
        Err(SvsmError::InvalidAddress)
    } else {
        Ok(())
    }
}

pub fn copy_from_user(src: VirtAddr, dst: &mut [u8]) -> Result<(), SvsmError> {
    let source = src.bits();
    let destination = dst.as_mut_ptr() as usize;
    let size = dst.len();

    check_bounds_user(source, size)?;

    // SAFETY: Safe because the copy only happens to the memory belonging to
    // the dst slice from user-mode memory.
    unsafe {
        let _guard = UserAccessGuard::new();
        copy_bytes(source, destination, size)
    }
}

pub fn copy_to_user(src: &[u8], dst: VirtAddr) -> Result<(), SvsmError> {
    let source = src.as_ptr() as usize;
    let destination = dst.bits();
    let size = src.len();

    check_bounds_user(destination, size)?;

    // SAFETY: Only reads data from with the slice and copies to an address
    // guaranteed to be in user-space.
    unsafe {
        let _guard = UserAccessGuard::new();
        copy_bytes(source, destination, size)
    }
}

fn checked_guest_region(start: PhysAddr, size: usize) -> Result<MemoryRegion<PhysAddr>, SvsmError> {
    let region = MemoryRegion::checked_new(start, size).ok_or(SvsmError::Mem)?;
    if !valid_phys_region(&region) {
        return Err(SvsmError::InvalidAddress);
    }
    Ok(region)
}

/// Reads a slice of bytes from a physical address region outside of SVSM use.
///
/// # Safety
///
/// The caller must ensure that dst..dst+size is memory that it owns.
///
/// # Arguments
///
/// * `src`: The physical address designating the start of continguous physical
///   memory to read from.
/// * `dst`: The pointer to the beginning of the SVSM memory range to populate.
/// * `size`: The number of bytes to write from src to dst.
///
/// # Returns
///
/// This function returns a `Result` that indicates the success or failure of the operation.
/// If the physical address region cannot be mapped, it returns `Err(SvsmError::Mem)`.
/// If the physical address region cannot be read, it returns `Err(SvsmError::Fault)`.
/// If the physical address region is not allocated to the guest, it returns
///   `Err(SvsmError::InvalidAddress)`.
pub unsafe fn copy_from_guest(src: PhysAddr, dst: *mut u8, size: usize) -> Result<(), SvsmError> {
    let region = checked_guest_region(src, size)?;
    let start = region.start().page_align();
    let offset = region.start().page_offset();
    let end = region.end().page_align_up();
    let destination = dst as usize;

    // SAFETY: Only reads data from a region outside the SVSM.
    unsafe {
        let guard = PerCPUPageMappingGuard::create(start, end, 0)?;
        let source = guard.virt_addr().bits() + offset;
        copy_bytes(source, destination, size)
    }
}

/// Reads a slice of bytes from a physical address region outside of SVSM use.
///
/// # Arguments
///
/// * `src`: The physical address designating the start of continguous physical
///   memory to read from.
/// * `dst`: A mutable slice of SVSM memory to populate from src.
///
/// # Returns
///
/// This function returns a `Result` that indicates the success or failure of the operation.
/// If the physical address region cannot be mapped, it returns `Err(SvsmError::Mem)`.
/// If the physical address region cannot be read, it returns `Err(SvsmError::Fault)`.
/// If the physical address region is not allocated to the guest, it returns
///   `Err(SvsmError::InvalidAddress)`.
pub fn copy_slice_from_guest(src: PhysAddr, dst: &mut [u8]) -> Result<(), SvsmError> {
    // SAFETY: The safety property of slices ensures the memory is owned and mutable.
    unsafe { copy_from_guest(src, dst.as_mut_ptr(), dst.len()) }
}

/// Writes a slice of bytes to a physical address region outside of SVSM use.
///
/// # Arguments
///
/// * `src`: The byte slice to write to guest memory.
/// * `dst`: The physical address designating the start of continguous physical
///   memory to write to.
///
/// # Returns
///
/// This function returns a `Result` that indicates the success or failure of the operation.
/// If the physical address region cannot be mapped, it returns `Err(SvsmError::Mem)`.
/// If the physical address region cannot be read, it returns `Err(SvsmError::Fault)`.
/// If the physical address region is not allocated to the guest, it returns
///   `Err(SvsmError::InvalidAddress)`.
pub fn copy_slice_to_guest(src: &[u8], dst: PhysAddr) -> Result<(), SvsmError> {
    let size = src.len();
    let region = checked_guest_region(dst, src.len())?;
    let start = region.start().page_align();
    let offset = region.start().page_offset();
    let end = region.end().page_align_up();
    let source = src.as_ptr() as usize;

    // SAFETY: Only reads data from a region outside the SVSM.
    unsafe {
        let guard = PerCPUPageMappingGuard::create(start, end, 0)?;
        let destination = guard.virt_addr().bits() + offset;
        copy_bytes(source, destination, size)
    }
}

/// Reads a vector of bytes from a physical address region outside of SVSM use.
///
/// # Arguments
///
/// * `src`: The physical address designating the start of continguous physical
///   memory to read from.
/// * `size`: The length of the physical address region to read into a vector.
///
/// # Returns
///
/// This function returns a `Result` that indicates the success or failure of the operation.
/// On success, returns a vector of length `size`.
/// If the physical address region cannot be mapped, it returns `Err(SvsmError::Mem)`.
/// If the physical address region cannot be read, it returns `Err(SvsmError::Fault)`.
/// If the physical address region is not allocated to the guest, it returns
///   `Err(SvsmError::InvalidAddress)`.
pub fn read_bytes_from_guest(src: PhysAddr, size: usize) -> Result<Vec<u8>, SvsmError> {
    let mut result = Vec::with_capacity(size);
    // SAFETY: The vector's capacity, `size` has been populated by copy_from_guest.
    // The translation of bytes to T are checked.
    unsafe {
        copy_from_guest(src, result.as_mut_ptr(), size)?;
        result.set_len(size);
    }
    Ok(result)
}

/// Reads an instance of T from a physical address region outside of SVSM use.
///
/// # Arguments
///
/// * `src`: The physical address designating the start of continguous physical
///   memory to read from.
///
/// # Returns
///
/// This function returns a `Result` that indicates the success or failure of the operation.
/// On success, returns an instance of T.
/// If the physical address region cannot be mapped, it returns `Err(SvsmError::Mem)`.
/// If the physical address region cannot be read, it returns `Err(SvsmError::Fault)`.
/// If the physical address region is not allocated to the guest, it returns
///   `Err(SvsmError::InvalidAddress)`.
pub fn read_from_guest<T: KnownLayout + Sized>(src: PhysAddr) -> Result<T, SvsmError> {
    let mut t: MaybeUninit<T> = MaybeUninit::uninit();
    // SAFETY: copy_from_guest does not read `t`, so it's safe to take a mutable pointer.
    // The `t` layout is known, so populating through the casted *mut u8 is safe.
    // The size of T is allocated on the SVSM stack, so it is fully owned.
    // copy_from_guest populates the full contents of t so it is same to assume t is initialized.
    unsafe {
        copy_from_guest(src, t.as_mut_ptr().cast::<u8>(), size_of::<T>())?;
        Ok(t.assume_init())
    }
}

/// Writes a value to a physical address region outside of SVSM use.
///
/// # Arguments
///
/// * `v`: The value to write to guest memory
/// * `dst`: The physical address designating the start of continguous physical
///   memory to write to.
///
/// # Returns
///
/// This function returns a `Result` that indicates the success or failure of the operation.
/// If the physical address region cannot be mapped, it returns `Err(SvsmError::Mem)`.
/// If the physical address region cannot be read, it returns `Err(SvsmError::Fault)`.
/// If the physical address region is not allocated to the guest, it returns
///   `Err(SvsmError::InvalidAddress)`.
#[inline]
pub fn write_to_guest<T: IntoBytes + Immutable>(v: &T, dst: PhysAddr) -> Result<(), SvsmError> {
    copy_slice_to_guest(v.as_bytes(), dst)
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
