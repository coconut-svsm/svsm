// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::{Address, VirtAddr};
use crate::error::SvsmError;

use core::arch::asm;
use core::mem::{size_of, MaybeUninit};

#[allow(dead_code)]
#[inline]
unsafe fn read_u8(v: VirtAddr) -> Result<u8, SvsmError> {
    let mut rcx: u64;
    let mut val: u64;

    asm!("1: movb ({0}), {1}",
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

    let ret: u8 = (val & 0xff) as u8;
    if rcx == 0 {
        Ok(ret)
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

pub struct GuestPtr<T>
where
    T: Sized + Copy,
{
    ptr: *mut T,
}

impl<T: Sized + Copy> GuestPtr<T> {
    pub fn new(v: VirtAddr) -> Self {
        Self {
            ptr: v.as_mut_ptr::<T>(),
        }
    }

    pub fn from_ptr(p: *mut T) -> Self {
        Self { ptr: p }
    }

    pub fn read(&self) -> Result<T, SvsmError> {
        let mut buf = MaybeUninit::<T>::uninit();

        unsafe {
            do_movsb(self.ptr, buf.as_mut_ptr())?;
            Ok(buf.assume_init())
        }
    }

    pub fn write(&self, buf: T) -> Result<(), SvsmError> {
        let src = &buf as *const T;

        unsafe { do_movsb(src, self.ptr) }
    }

    pub fn write_ref(&self, buf: &T) -> Result<(), SvsmError> {
        let src = buf as *const T;

        unsafe { do_movsb(src, self.ptr) }
    }

    pub fn cast<N: Sized + Copy>(&self) -> GuestPtr<N>
    where
        N: Sized + Copy,
    {
        GuestPtr::<N>::from_ptr(self.ptr.cast::<N>())
    }

    pub fn offset(&self, count: isize) -> Self {
        unsafe { GuestPtr::from_ptr(self.ptr.offset(count)) }
    }
}
