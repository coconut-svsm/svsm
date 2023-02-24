// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use crate::types::VirtAddr;

use core::marker::PhantomData;
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
unsafe fn do_movsb(src: VirtAddr, dst: VirtAddr, size: usize) -> Result<(),()> {
    let mut rcx : u64; 

    asm!("1:cld
            rep movsb
          2:
         .pushsection \"__exception_table\",\"a\"
         .balign 16
         .quad (1b)
         .quad (2b)
         .popsection",
            in("rsi") src,
            in("rdi") dst,
            in("rcx") size,
            lateout("rcx") rcx,
            options(att_syntax, nostack));

    if rcx == 0 { Ok(()) } else { Err(()) }
}

unsafe fn read_generic<T>(src: VirtAddr, buffer : &mut T) -> Result<(),()>
where
    T : Sized + Copy
{
    let dst = (buffer as *mut T) as VirtAddr;
    let size = size_of::<T>();

    do_movsb(src, dst, size)
}

unsafe fn write_generic<T>(dst: VirtAddr, buffer : &T) -> Result<(),()>
where
    T : Sized + Copy
{
    let src = (buffer as *const T) as VirtAddr;
    let size = size_of::<T>();

    do_movsb(src, dst, size)
}

pub struct GuestPtr<T>
where
    T : Sized + Copy
{
    addr: VirtAddr,
    _phantom: PhantomData<T>,
}

impl<T : Sized + Copy> GuestPtr<T> {
    pub fn new(v: VirtAddr) -> Self {
        GuestPtr { addr: v, _phantom: PhantomData }
    }

    pub fn read(&self) -> Result<T,()> {
        let result;
        let mut buf : T = unsafe { MaybeUninit::uninit().assume_init() };

        unsafe { result = read_generic::<T>(self.addr, &mut buf); }

        if let Ok(_) = result { Ok(buf) } else { Err(()) }
    }

    pub fn write(&self, buf: T) -> Result<T,()> {
        let result;

        unsafe { result = write_generic::<T>(self.addr, &buf); }

        if let Ok(_) = result { Ok(buf) } else { Err(()) }
    }

    pub fn write_ref(&self, buf: &T) -> Result<T,()> {
        let result;

        unsafe { result = write_generic::<T>(self.addr, &buf); }

        if let Ok(_) = result { Ok(*buf) } else { Err(()) }
    }

    pub fn cast<N : Sized + Copy>(&self) -> GuestPtr<N>
    where
        N : Sized + Copy
    {
        GuestPtr::<N>::new(self.addr)
    }

    pub fn offset(&self, count: usize) -> Self {
        let offset = count * size_of::<T>();
        GuestPtr::new(self.addr + offset)
    }
}
