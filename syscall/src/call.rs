// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Intel Corporation.
//
// Author: Chuanxiao Dong <chuanxiao.dong@intel.com>

use core::arch::asm;

/// Macro to generate system call functions with varying numbers of arguments.
macro_rules! syscall {
    ($($name:ident($a:ident, $($b:ident, $($c:ident, $($d:ident, $($e:ident, $($f:ident, )?)?)?)?)?);)+) => {
        $(
            /// Performs a system call with arguments.
            ///
            /// # Safety
            ///
            /// This function is unsafe because it performs a system call.
            /// The kernel should check the syscall number and return the
            /// expected result back.
            #[allow(dead_code)]
            pub unsafe fn $name($a: u64, $($b: u64, $($c: u64, $($d: u64, $($e: u64, $($f: u64)?)?)?)?)?) -> Result<u64, SysCallError> {
                let mut ret = $a;
                // SAFETY: This block is required to perform a raw system call.
                // The caller must ensure that the syscall number and arguments
                // are valid.
                unsafe {
                    asm!(
                        "int 0x80",
                        inout("rax") ret,
                        $(
                            in("rdi") $b,
                            $(
                                in("rsi") $c,
                                $(
                                    in("r8") $d,
                                    $(
                                        in("r9") $e,
                                        $(
                                            in("r10") $f,
                                        )?
                                    )?
                                )?
                            )?
                        )?
                        out("rcx") _,
                        out("r11") _,
                        options(nostack),
                    );
                }

                if ret > (u64::MAX - u64::from(u16::MAX)) {
                    return Err(SysCallError::from(ret as i32));
                }
                Ok(ret)
            }
        )+
    };
}

syscall! {
    syscall0(a,);
    syscall1(a, b,);
    syscall2(a, b, c,);
    syscall3(a, b, c, d,);
    syscall4(a, b, c, d, e,);
    syscall5(a, b, c, d, e, f,);
}

#[derive(Clone, Copy, Debug)]
pub enum SysCallError {
    EINVAL = -1,
    ENOSYS = -2,
    ENOMEM = -3,
    EPERM = -4,
    EFAULT = -5,
    EBUSY = -6,
    ENOTFOUND = -7,
    ENOTSUPP = -8,
    EEXIST = -9,
    UNKNOWN = -128,
}

impl From<i32> for SysCallError {
    fn from(e: i32) -> SysCallError {
        match e {
            -1 => SysCallError::EINVAL,
            -2 => SysCallError::ENOSYS,
            -3 => SysCallError::ENOMEM,
            -4 => SysCallError::EPERM,
            -5 => SysCallError::EFAULT,
            -6 => SysCallError::EBUSY,
            -7 => SysCallError::ENOTFOUND,
            -8 => SysCallError::ENOTSUPP,
            -9 => SysCallError::EEXIST,
            _ => SysCallError::UNKNOWN,
        }
    }
}
