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
    USER_MEM_END, USER_MEM_START, memory::valid_phys_region, ptguards::PerCPUPageMappingGuard,
};
use crate::utils::MemoryRegion;
use alloc::string::String;
use alloc::vec::Vec;
use core::arch::asm;
use core::borrow::Borrow;
use core::ffi::c_char;
use core::mem::{MaybeUninit, size_of};
use core::ptr::{self, NonNull};
use core::slice;
use syscall::PATH_MAX;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

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
        asm!("1: rep movsb
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

/// Zeroes `size` number of bytes at `dst`, catching any fault that / might
/// happen during the operation.
///
/// # Safety
///
/// The caller must make sure that writing to `dst` does not harm memory safety.
unsafe fn clear_bytes(dst: *mut u8, size: usize) -> Result<(), SvsmError> {
    let mut rcx: u64;

    // SAFETY: The safety requirements of the function need to be met. Will
    // write only `size` zero bytes at `dst`.
    unsafe {
        asm!("1: rep stosb
              2:
                 .pushsection \"__exception_table\",\"a\"
                 .balign 16
                 .quad (1b)
                 .quad (2b)
                 .popsection",
                 inout("rdi") dst.expose_provenance() => _,
                 inout("rcx") size => rcx,
                 in("rax") 0,
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
unsafe fn do_movsb<T>(src: *const T, dst: *mut T) -> Result<(), SvsmError> {
    let size: usize = size_of::<T>();

    // SAFETY: Only safe when safety requirements for do_movsb() are fulfilled.
    unsafe { copy_bytes(src.cast(), dst.cast(), size) }
}

/// A pointer wrapper that safely handles faults when accessing memory.
#[derive(Debug)]
pub struct TryPtr<T: ?Sized> {
    ptr: *mut T,
}

impl<T> TryPtr<T> {
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

    /// Attempts to read the `T` behind the pointer, verifying that it has
    /// a valid representation in the process. This may be used for types
    /// for which [not all bit patterns are valid][valid-instance].
    ///
    /// [valid-instance]: <https://docs.rs/zerocopy/latest/zerocopy/trait.TryFromBytes.html#what-is-a-valid-instance>
    ///
    /// # Safety
    ///
    /// See safety considerations for [`TryPtr::read()`].
    ///
    /// # Errors
    ///
    /// * If the access caused a fault, this returns `Err(SvsmError::Fault)`.
    /// * If the read data did not have a valid format for `T`, this returns
    ///   `Err(SvsmError::Mem)`.
    pub unsafe fn try_read(&self) -> Result<T, SvsmError>
    where
        T: TryFromBytes,
    {
        let mut buf = MaybeUninit::<T>::uninit();
        let dst = buf.as_mut_ptr();
        // SAFETY: Safe because `dst` is on the local stack. The data is
        // explicitly uninitialized and no one else has access to it.
        // Creating the slice is safe because:
        // * `do_movsb()` fills the buffer completely or fails, so memory
        //   is initialized.
        // * The slice has the same size as `T`.
        // * The slice has no invalid reprensentations nor alignment
        //   requirements.
        let bytes = unsafe {
            do_movsb(self.ptr, dst)?;
            slice::from_raw_parts(dst.cast::<u8>(), size_of::<T>())
        };

        T::try_read_from_bytes(bytes).map_err(|_| SvsmError::Mem)
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
    pub unsafe fn read(&self) -> Result<T, SvsmError>
    where
        T: FromBytes,
    {
        let mut buf = MaybeUninit::<T>::uninit();

        // SAFETY: Safe because `dst` is on the local stack. The data is
        // explicitly uninitialized and no one else has access to it.
        unsafe {
            do_movsb(self.ptr, buf.as_mut_ptr())?;
            Ok(buf.assume_init())
        }
    }

    /// Writes `buf` into the memory pointed to by this `TryPtr`.
    /// `buf` may be an owned instance of `T` or a reference.
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
    pub unsafe fn write<B>(&self, buf: B) -> Result<(), SvsmError>
    where
        B: Borrow<T>,
        T: IntoBytes,
    {
        let src = buf.borrow();
        // SAFETY: Safe when self.ptr does not point to SVSM memory because
        // then the write can not harm memory safety.
        unsafe { do_movsb(src, self.ptr) }
    }

    #[inline]
    pub const fn cast<N>(&self) -> TryPtr<N> {
        TryPtr::from_ptr(self.ptr.cast())
    }

    #[inline]
    pub fn offset(&self, count: isize) -> Self {
        TryPtr::from_ptr(self.ptr.wrapping_offset(count))
    }
}

impl<T> TryPtr<[T]> {
    /// Creates a `TryPtr<[T]>` pointing to `len` elements starting at `v`.
    #[inline]
    pub fn new(v: VirtAddr, len: usize) -> Self {
        Self {
            ptr: ptr::slice_from_raw_parts_mut(v.as_mut_ptr::<T>(), len),
        }
    }

    /// Returns the number of elements in the slice.
    #[inline]
    pub const fn len(&self) -> usize {
        self.ptr.len()
    }

    /// Returns `true` if the slice contains no elements.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reads element at `index`.
    ///
    /// # Safety
    ///
    /// The caller must verify that the entire slice is appropriate to read,
    /// as this function does not validate the address range.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::InvalidAddress`] if `index >= len`, or
    /// [`SvsmError::Fault`] if the access faults.
    pub unsafe fn read(&self, index: usize) -> Result<T, SvsmError>
    where
        T: FromBytes,
    {
        if index >= self.len() {
            return Err(SvsmError::InvalidAddress);
        }
        // SAFETY: bounds-checked above; remaining requirements from caller.
        unsafe { TryPtr::from_ptr((self.ptr as *mut T).wrapping_add(index)).read() }
    }

    /// Writes `val` to element at `index` in this `TryPtr<[T]>`.
    /// `val` may be an owned instance of `T` or a reference.
    ///
    /// # Safety
    ///
    /// The caller must verify that the entire slice is appropriate to write,
    /// as this function does not validate the address range.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::InvalidAddress`] if `index >= len`, or
    /// [`SvsmError::Fault`] if the access faults.
    pub unsafe fn write<B>(&self, index: usize, val: B) -> Result<(), SvsmError>
    where
        B: Borrow<T>,
        T: IntoBytes,
    {
        if index >= self.len() {
            return Err(SvsmError::InvalidAddress);
        }
        // SAFETY: bounds-checked above; remaining requirements from caller.
        unsafe { TryPtr::from_ptr((self.ptr as *mut T).wrapping_add(index)).write(val) }
    }

    /// Reads all elements and copies them into `dst`.
    ///
    /// # Safety
    ///
    /// The caller must verify that the entire backing memory is appropriate
    /// to read.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::Mem`] if `dst.len() != self.len()`, or
    /// [`SvsmError::Fault`] if the copy faults.
    pub unsafe fn read_to_slice(&self, dst: &mut [T]) -> Result<(), SvsmError>
    where
        T: FromBytes,
    {
        if dst.len() != self.len() {
            return Err(SvsmError::Mem);
        }
        // SAFETY: dst is a valid slice; source requirements come from caller.
        unsafe {
            copy_bytes(
                (self.ptr as *const T).cast::<u8>(),
                dst.as_mut_ptr().cast::<u8>(),
                self.len() * size_of::<T>(),
            )
        }
    }

    /// Reads all elements and copies them into a newly allocated `Vec`.
    ///
    /// # Safety
    ///
    /// The caller must verify that the entire backing memory is appropriate
    /// to read.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::Fault`] if the copy faults.
    pub unsafe fn read_to_vec(&self) -> Result<Vec<T>, SvsmError>
    where
        T: FromBytes,
    {
        let mut v = Vec::with_capacity(self.len());
        let dst = v.spare_capacity_mut();
        // SAFETY: `dst` is guaranteed to point to valid and large enough
        // memory. If `copy_bytes()` succeeds, `self.len()` elements have
        // been successfully initialized.
        unsafe {
            copy_bytes(
                self.ptr.cast_const().cast::<u8>(),
                dst.as_mut_ptr().cast::<u8>(),
                self.len() * size_of::<T>(),
            )?;
            v.set_len(self.len());
        }
        Ok(v)
    }

    /// Writes all elements from `src`.
    ///
    /// # Safety
    ///
    /// The caller must verify that the entire backing memory is appropriate
    /// to write.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::Mem`] if `src.len() != self.len()`, or
    /// [`SvsmError::Fault`] if the copy faults.
    pub unsafe fn write_from_slice(&self, src: &[T]) -> Result<(), SvsmError>
    where
        T: IntoBytes,
    {
        if src.len() != self.len() {
            return Err(SvsmError::Mem);
        }
        // SAFETY: src is a valid slice; destination requirements come from caller.
        unsafe {
            copy_bytes(
                src.as_ptr().cast::<u8>(),
                (self.ptr as *mut T).cast::<u8>(),
                self.len() * size_of::<T>(),
            )
        }
    }
}

impl TryPtr<[u8]> {
    /// # Safety
    ///
    /// The caller must verify that the entire backing memory is appropriate
    /// to write.
    pub unsafe fn zero_fill(&self) -> Result<(), SvsmError> {
        // SAFETY: bounds limited to `self.len()`, the rest is delegated to
        // the caller
        unsafe { clear_bytes(self.ptr.cast::<u8>(), self.len()) }
    }
}

impl<T> From<NonNull<T>> for TryPtr<T> {
    fn from(value: NonNull<T>) -> Self {
        Self::from_ptr(value.as_ptr())
    }
}

impl<T: FromBytes + IntoBytes> InsnMachineMem<T> for TryPtr<T> {
    /// # Safety
    ///
    /// See the TryPtr's read() method documentation for safety requirements.
    unsafe fn mem_read(&self) -> Result<T, InsnError> {
        // SAFETY: Safe when TryPtr::read safety requirements are met.
        unsafe { self.read().map_err(|_| InsnError::MemRead) }
    }

    /// # Safety
    ///
    /// See the TryPtr's write() method documentation for safety requirements.
    unsafe fn mem_write(&mut self, data: T) -> Result<(), InsnError> {
        // SAFETY: Safe when TryPtr::write safety requirements are met.
        unsafe { self.write(data).map_err(|_| InsnError::MemWrite) }
    }
}

impl PerCPUPageMappingGuard {
    /// Returns a [`GuestPtr<T>`] at `offset` bytes into the mapped region.
    ///
    /// # Errors
    ///
    /// * [`SvsmError::InvalidAddress`] if the access would exceed the mapped region or
    ///   fall outside guest memory.
    /// * [`SvsmError::Mem`] if integer overflow occurs.
    pub fn guest_ptr<T>(&self, offset: usize) -> Result<GuestPtr<'_, T>, SvsmError> {
        let start = self.phys_base().checked_add(offset).ok_or(SvsmError::Mem)?;
        let region = checked_guest_region(start, size_of::<T>())?;
        if !self.phys_region().contains_region(&region) {
            return Err(SvsmError::InvalidAddress);
        }
        Ok(GuestPtr {
            _guard: self,
            ptr: TryPtr::<T>::new(self.virt_addr() + offset),
        })
    }

    /// Returns a [`GuestPtr<[T]>`] for `len` elements at `offset` bytes into
    /// the mapped region.
    ///
    /// # Errors
    ///
    /// * [`SvsmError::InvalidAddress`] if the access would exceed the mapped region or
    ///   fall outside guest memory.
    /// * [`SvsmError::Mem`] if integer overflow occurs.
    pub fn guest_slice<T>(
        &self,
        offset: usize,
        len: usize,
    ) -> Result<GuestPtr<'_, [T]>, SvsmError> {
        let start = self.phys_base().checked_add(offset).ok_or(SvsmError::Mem)?;
        let size = len.checked_mul(size_of::<T>()).ok_or(SvsmError::Mem)?;
        let region = checked_guest_region(start, size)?;
        if !self.phys_region().contains_region(&region) {
            return Err(SvsmError::InvalidAddress);
        }
        Ok(GuestPtr {
            _guard: self,
            ptr: TryPtr::<[T]>::new(self.virt_addr() + offset, len),
        })
    }
}

/// A pointer to a validated region of lower-VMPL guest memory, anchored to a
/// [`PerCPUPageMappingGuard`] that keeps the underlying page mapping live.
///
/// Created via [`PerCPUPageMappingGuard::guest_ptr`] or
/// [`PerCPUPageMappingGuard::guest_slice`].
#[derive(Debug)]
pub struct GuestPtr<'a, T: ?Sized> {
    _guard: &'a PerCPUPageMappingGuard,
    ptr: TryPtr<T>,
}

impl<T> GuestPtr<'_, T> {
    /// Reads the value from guest memory.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::Fault`] if the access faults unexpectedly.
    pub fn read(&self) -> Result<T, SvsmError>
    where
        T: FromBytes,
    {
        // SAFETY: bounds were verified at construction
        unsafe { self.ptr.read() }
    }

    /// Attempts to read the value from guest memory, validating its bit
    /// pattern.
    ///
    /// # Errors
    ///
    /// * [`SvsmError::Fault`] if the access faults.
    /// * [`SvsmError::Mem`] if the data is not a valid instance of `T`.
    pub fn try_read(&self) -> Result<T, SvsmError>
    where
        T: TryFromBytes,
    {
        // SAFETY: bounds were verified at construction
        unsafe { self.ptr.try_read() }
    }

    /// Writes `val` to guest memory.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::Fault`] if the access faults.
    pub fn write<B>(&self, val: B) -> Result<(), SvsmError>
    where
        B: Borrow<T>,
        T: IntoBytes,
    {
        // SAFETY: bounds were verified at construction
        unsafe { self.ptr.write(val) }
    }
}

impl<T> GuestPtr<'_, [T]> {
    /// Returns the number of elements in the slice.
    pub const fn len(&self) -> usize {
        self.ptr.len()
    }

    /// Returns `true` if the slice contains no elements.
    pub const fn is_empty(&self) -> bool {
        self.ptr.is_empty()
    }

    /// Reads element at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::InvalidAddress`] if `index >= len`, or
    /// [`SvsmError::Fault`] if the access faults.
    pub fn read(&self, index: usize) -> Result<T, SvsmError>
    where
        T: FromBytes,
    {
        // SAFETY: bounds were verified at construction
        unsafe { self.ptr.read(index) }
    }

    /// Writes `val` to element at `index`.
    /// `val` may be an owned instance of `T` or a reference.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::InvalidAddress`] if `index >= len`, or
    /// [`SvsmError::Fault`] if the access faults.
    pub fn write<B>(&self, index: usize, val: B) -> Result<(), SvsmError>
    where
        B: Borrow<T>,
        T: IntoBytes,
    {
        // SAFETY: bounds were verified at construction
        unsafe { self.ptr.write(index, val) }
    }

    /// Reads all elements and copies them into `dst`.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::Mem`] if `dst.len() != self.len()`, or
    /// [`SvsmError::Fault`] if the copy faults.
    pub fn read_to_slice(&self, dst: &mut [T]) -> Result<(), SvsmError>
    where
        T: FromBytes,
    {
        // SAFETY: bounds were verified at construction
        unsafe { self.ptr.read_to_slice(dst) }
    }

    pub fn read_to_vec(&self) -> Result<Vec<T>, SvsmError>
    where
        T: FromBytes,
    {
        // SAFETY: bounds were verified at construction
        unsafe { self.ptr.read_to_vec() }
    }

    /// Writes all elements from `src`.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::Mem`] if `src.len() != self.len()`, or
    /// [`SvsmError::Fault`] if the copy faults.
    pub fn write_from_slice(&self, src: &[T]) -> Result<(), SvsmError>
    where
        T: IntoBytes,
    {
        // SAFETY: bounds were verified at construction
        unsafe { self.ptr.write_from_slice(src) }
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
pub struct UserPtr<T: ?Sized> {
    ptr: TryPtr<T>,
}

impl<T> UserPtr<T> {
    /// Constructs a `UserPtr` pointing to `v`, checking that the entire object
    /// falls within userspace.
    #[inline]
    pub fn new(v: VirtAddr) -> Result<Self, SvsmError> {
        let userspace = MemoryRegion::from_addresses(USER_MEM_START, USER_MEM_END);
        let region =
            MemoryRegion::checked_new(v, size_of::<T>()).ok_or(SvsmError::InvalidAddress)?;
        if !userspace.contains_region(&region) {
            return Err(SvsmError::InvalidAddress);
        }
        Ok(Self {
            ptr: TryPtr::<T>::new(v),
        })
    }

    #[inline]
    pub fn read(&self) -> Result<T, SvsmError>
    where
        T: FromBytes,
    {
        let _guard = UserAccessGuard::new();
        // SAFETY: bounds were verified at construction.
        unsafe { self.ptr.read() }
    }

    /// Attempts to read the `T` behind the pointer, verifying it has a valid
    /// representation in the process (see [`TryPtr::try_read`]).
    #[inline]
    pub fn try_read(&self) -> Result<T, SvsmError>
    where
        T: TryFromBytes,
    {
        let _guard = UserAccessGuard::new();
        // SAFETY: bounds were verified at construction.
        unsafe { self.ptr.try_read() }
    }

    #[inline]
    pub fn write<B>(&self, buf: B) -> Result<(), SvsmError>
    where
        B: Borrow<T>,
        T: IntoBytes,
    {
        let _guard = UserAccessGuard::new();
        // SAFETY: bounds were verified at construction.
        unsafe { self.ptr.write(buf) }
    }

    #[inline]
    pub fn cast<N>(&self) -> Result<UserPtr<N>, SvsmError> {
        let vaddr = VirtAddr::from(self.ptr.ptr);
        UserPtr::<N>::new(vaddr)
    }

    #[inline]
    pub fn offset(&self, count: isize) -> Result<Self, SvsmError> {
        Self::new(VirtAddr::from(self.ptr.offset(count).ptr))
    }
}

impl UserPtr<c_char> {
    /// Reads a null-terminated C string from the user space.
    /// Allocates memory for the string and returns a `String`.
    pub fn read_c_string(&self) -> Result<String, SvsmError> {
        let mut buffer = Vec::new();

        for offset in 0..PATH_MAX {
            let current_ptr = self.offset(offset as isize)?;
            let char_result = current_ptr.read()?;
            match char_result {
                0 => return String::from_utf8(buffer).map_err(|_| SvsmError::InvalidUtf8),
                c => buffer.push(c as u8),
            }
        }
        Err(SvsmError::InvalidBytes)
    }
}

impl<T> UserPtr<[T]> {
    /// Constructs a `UserPtr<[T]>` pointing to `len` elements at `v`,
    /// checking that the entire object falls within userspace.
    #[inline]
    pub fn new(v: VirtAddr, len: usize) -> Result<Self, SvsmError> {
        let userspace = MemoryRegion::from_addresses(USER_MEM_START, USER_MEM_END);
        let region = len
            .checked_mul(size_of::<T>())
            .and_then(|size| MemoryRegion::checked_new(v, size))
            .ok_or(SvsmError::InvalidAddress)?;
        if !userspace.contains_region(&region) {
            return Err(SvsmError::InvalidAddress);
        }
        Ok(Self {
            ptr: TryPtr::<[T]>::new(v, len),
        })
    }

    /// Returns the number of elements in the slice.
    #[inline]
    pub const fn len(&self) -> usize {
        self.ptr.len()
    }

    /// Returns `true` if the slice contains no elements.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.ptr.is_empty()
    }

    /// Reads element at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::InvalidAddress`] if `index >= len`, or
    /// [`SvsmError::Fault`] if the access faults.
    #[inline]
    pub fn read(&self, index: usize) -> Result<T, SvsmError>
    where
        T: FromBytes,
    {
        let _guard = UserAccessGuard::new();
        // SAFETY: bounds were verified at construction.
        unsafe { self.ptr.read(index) }
    }

    /// Writes `val` to element at `index`.
    /// `val` may be an owned instance of `T` or a reference.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::InvalidAddress`] if `index >= len`, or
    /// [`SvsmError::Fault`] if the access faults.
    #[inline]
    pub fn write<B>(&self, index: usize, val: B) -> Result<(), SvsmError>
    where
        B: Borrow<T>,
        T: IntoBytes,
    {
        let _guard = UserAccessGuard::new();
        // SAFETY: bounds were verified at construction.
        unsafe { self.ptr.write(index, val) }
    }

    /// Copies all elements into `dst`.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::Mem`] if `dst.len() != self.len()`, or
    /// [`SvsmError::Fault`] if the access faults.
    #[inline]
    pub fn read_to_slice(&self, dst: &mut [T]) -> Result<(), SvsmError>
    where
        T: FromBytes,
    {
        let _guard = UserAccessGuard::new();
        // SAFETY: bounds were verified at construction.
        unsafe { self.ptr.read_to_slice(dst) }
    }

    /// Copies all elements from `src` into the slice.
    ///
    /// # Errors
    ///
    /// Returns [`SvsmError::Mem`] if `src.len() != self.len()`, or
    /// [`SvsmError::Fault`] if the access faults.
    #[inline]
    pub fn write_from_slice(&self, src: &[T]) -> Result<(), SvsmError>
    where
        T: IntoBytes,
    {
        let _guard = UserAccessGuard::new();
        // SAFETY: bounds were verified at construction.
        unsafe { self.ptr.write_from_slice(src) }
    }
}

impl UserPtr<[u8]> {
    pub fn zero_fill(&self) -> Result<(), SvsmError> {
        let _guard = UserAccessGuard::new();
        // SAFETY: bounds were verified at construction.
        unsafe { self.ptr.zero_fill() }
    }
}

pub fn zero_user_mem(dst: VirtAddr, size: usize) -> Result<(), SvsmError> {
    UserPtr::<[u8]>::new(dst, size)?.zero_fill()
}

pub fn copy_from_user(src: VirtAddr, dst: &mut [u8]) -> Result<(), SvsmError> {
    UserPtr::<[u8]>::new(src, dst.len())?.read_to_slice(dst)
}

pub fn copy_to_user(src: &[u8], dst: VirtAddr) -> Result<(), SvsmError> {
    UserPtr::<[u8]>::new(dst, src.len())?.write_from_slice(src)
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
    let src_end = src
        .checked_add(dst.len())
        .and_then(|end| end.checked_page_align_up())
        .ok_or(SvsmError::Mem)?;
    PerCPUPageMappingGuard::create(src.page_align(), src_end, 0)?
        .guest_slice::<u8>(src.page_offset(), dst.len())?
        .read_to_slice(dst)
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
    let dst_end = dst
        .checked_add(src.len())
        .and_then(|end| end.checked_page_align_up())
        .ok_or(SvsmError::Mem)?;
    PerCPUPageMappingGuard::create(dst.page_align(), dst_end, 0)?
        .guest_slice::<u8>(dst.page_offset(), src.len())?
        .write_from_slice(src)
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
    let src_end = src
        .checked_add(size)
        .and_then(|end| end.checked_page_align_up())
        .ok_or(SvsmError::Mem)?;
    PerCPUPageMappingGuard::create(src.page_align(), src_end, 0)?
        .guest_slice::<u8>(src.page_offset(), size)?
        .read_to_vec()
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
pub fn read_from_guest<T: KnownLayout + FromBytes + Sized>(src: PhysAddr) -> Result<T, SvsmError> {
    let src_end = src
        .checked_add(size_of::<T>())
        .and_then(|end| end.checked_page_align_up())
        .ok_or(SvsmError::Mem)?;
    PerCPUPageMappingGuard::create(src.page_align(), src_end, 0)?
        .guest_ptr::<T>(src.page_offset())?
        .read()
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
    let dst_end = dst
        .checked_add(size_of::<T>())
        .and_then(|end| end.checked_page_align_up())
        .ok_or(SvsmError::Mem)?;
    PerCPUPageMappingGuard::create(dst.page_align(), dst_end, 0)?
        .guest_ptr::<T>(dst.page_offset())?
        .write(v)
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
        let ptr = TryPtr::<[u8; 15]>::new(test_addr);
        // SAFETY: ptr points to test_buffer's virtual address
        let result = unsafe { ptr.read().unwrap() };

        assert_eq!(result, test_buffer);
    }

    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    #[cfg_attr(not(test_in_svsm), ignore = "Can only be run inside guest")]
    fn test_read_invalid_address() {
        let ptr = TryPtr::<u8>::new(VirtAddr::new(0xDEAD_BEEF));
        // SAFETY: ptr points to an invalid virtual address (0xDEADBEEF is
        // unmapped). ptr.read() will return an error but this is expected.
        let err = unsafe { ptr.read() };
        assert!(err.is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    fn test_read_valid_bit_pattern() {
        // Valid bit pattern for `bool`
        let mut buffer = [1u8];
        let ptr = TryPtr::<bool>::from_ptr(buffer.as_mut_ptr().cast());
        // SAFETY: the pointer points to a buffer on the stack with a size of 1
        // which is also the size of a bool, so we cannot read, out of bounds.
        let val = unsafe { ptr.try_read() };
        assert!(val.unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore = "inline assembly")]
    fn test_read_invalid_bit_pattern() {
        // Invalid bit pattern for `bool`
        let mut buffer = [2u8];
        let ptr = TryPtr::<bool>::from_ptr(buffer.as_mut_ptr().cast());
        // SAFETY: the pointer points to a buffer on the stack with a size of 1
        // which is also the size of a bool, so we cannot read, out of bounds.
        let val = unsafe { ptr.try_read() };
        assert!(matches!(val.unwrap_err(), SvsmError::Mem));
    }
}
