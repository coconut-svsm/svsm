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
                        "syscall",
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
                    return Err(SysCallError::from(ret as i64));
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

/// Defines [`SysCallError`] and the conversion from its numbers.
macro_rules! syscall_errors {
    ($($name:ident = $val:literal,)+) => {
        /// An error returned by a system call.
        ///
        /// The values are the negated Linux error numbers, which is how
        /// system calls return errors.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum SysCallError {
            $($name = $val,)+
            /// An error number this type does not have. It is the last
            /// number of the range Linux reserves for errors, which Linux
            /// does not assign.
            UNKNOWN = -4095,
        }

        impl SysCallError {
            #[cfg(test)]
            const ALL: &[Self] = &[$(Self::$name,)+];
        }

        impl From<i64> for SysCallError {
            fn from(number: i64) -> Self {
                match number {
                    $($val => Self::$name,)+
                    _ => Self::UNKNOWN,
                }
            }
        }
    };
}

syscall_errors! {
    EPERM = -1,
    ENOENT = -2,
    EIO = -5,
    EBADF = -9,
    ENOMEM = -12,
    EFAULT = -14,
    EBUSY = -16,
    EEXIST = -17,
    ENOTDIR = -20,
    EISDIR = -21,
    EINVAL = -22,
    ENOSYS = -38,
    ENOTEMPTY = -39,
    EOPNOTSUPP = -95,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_roundtrip() {
        for &err in SysCallError::ALL {
            assert_eq!(SysCallError::from(err as i64), err);
        }
        assert_eq!(SysCallError::ENOSYS as i64, -38);
        // Numbers that are not errors this type has.
        assert_eq!(SysCallError::from(0), SysCallError::UNKNOWN);
        assert_eq!(SysCallError::from(-4095), SysCallError::UNKNOWN);
    }
}
