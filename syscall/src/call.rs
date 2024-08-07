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
            pub unsafe fn $name($a: u64, $($b: u64, $($c: u64, $($d: u64, $($e: u64, $($f: u64)?)?)?)?)?) -> u64 {
                let mut ret = $a;
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

                ret
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
