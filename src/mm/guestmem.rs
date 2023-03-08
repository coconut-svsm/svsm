// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::VirtAddr;

use core::mem::{size_of, MaybeUninit};
use core::arch::asm;

#[allow(dead_code)]
#[inline]
unsafe fn read_u8(v: VirtAddr) -> Result<u8,()> {
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
            in(reg) v,
            out(reg) val,
            out("rcx") rcx,
            options(att_syntax, nostack));

    let ret: u8 = (val & 0xff) as u8;
    if rcx == 0 { Ok(ret) } else { Err(()) }
}

#[allow(dead_code)]
#[inline]
unsafe fn read_u16(v: VirtAddr) -> Result<u16,()> {
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
            in(reg) v,
            out(reg) val,
            out("rcx") rcx,
            options(att_syntax, nostack));

    let ret: u16 = (val & 0xffff) as u16;
    if rcx == 0 { Ok(ret) } else { Err(()) }
}

#[allow(dead_code)]
#[inline]
unsafe fn read_u32(v: VirtAddr) -> Result<u32,()> {
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
            in(reg) v,
            out(reg) val,
            out("rcx") rcx,
            options(att_syntax, nostack));

    let ret: u32 = (val & 0xffffffff) as u32;
    if rcx == 0 { Ok(ret) } else { Err(()) }
}

#[allow(dead_code)]
#[inline]
unsafe fn read_u64(v: VirtAddr) -> Result<u64,()> {
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
            in(reg) v,
            out(reg) val,
            out("rcx") rcx,
            options(att_syntax, nostack));

    if rcx == 0 { Ok(val) } else { Err(()) }
}

#[inline]
unsafe fn do_movsb<T>(src: *const T, dst: *mut T) -> Result<(),()> {
    let size: usize = size_of::<T>();
    let mut rcx : u64; 

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

    if rcx == 0 { Ok(()) } else { Err(()) }
}

pub struct GuestPtr<T>
where
    T : Sized + Copy
{
    ptr: *mut T,
}

impl<T : Sized + Copy> GuestPtr<T> {
    pub fn new(v: VirtAddr) -> Self {
        GuestPtr { ptr: v as *mut T}
    }

    pub fn from_ptr(p: *mut T) -> Self {
        GuestPtr { ptr: p }
    }

    pub fn read(&self) -> Result<T,()> {
        let mut buf = MaybeUninit::<T>::uninit();

        unsafe {
            do_movsb(self.ptr, buf.as_mut_ptr())?;
            Ok(buf.assume_init())
        }
    }

    pub fn write(&self, buf: T) -> Result<(),()> {
        let src = &buf as *const T;
        
        unsafe { do_movsb(src, self.ptr) }
    }

    pub fn write_ref(&self, buf: &T) -> Result<(),()> {
        let src = buf as *const T;

        unsafe { do_movsb(src, self.ptr) }
    }

    pub fn cast<N : Sized + Copy>(&self) -> GuestPtr<N>
    where
        N : Sized + Copy
    {
        GuestPtr::<N>::new(self.ptr as VirtAddr)
    }

    pub fn offset(&self, count: isize) -> Self {
        unsafe { GuestPtr::from_ptr(self.ptr.offset(count)) }
    }
}
