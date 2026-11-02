// SPDX-License-Identifier: MIT
//
// Copyright (c) 2026 Advanced Micro Devices, Inc
//
// Author: Mahmoud Nagy Adam <madam@amd.com>

/// First number of the range that is reserved for system calls that only the
/// SVSM has. Linux does not use numbers this high.
pub const NR_SVSM_BASE: u64 = 0x2000_0000;

/// Defines [`SysNo`] and the conversion from its numbers.
macro_rules! sys_numbers {
    ($($(#[$meta:meta])* $name:ident = $nr:expr,)+) => {
        /// The system calls of the SVSM.
        ///
        /// The calls that behave like their Linux x86-64 counterpart have
        /// its name and number. The other ones, which still have their own
        /// semantics, have a number in the range that starts at
        /// [`NR_SVSM_BASE`] and a name starting with `Svsm`. They move to
        /// the Linux number when they are converted.
        #[repr(u64)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum SysNo {
            $($(#[$meta])* $name = $nr,)+
        }

        impl SysNo {
            #[cfg(test)]
            const ALL: &[Self] = &[$(Self::$name,)+];
        }

        impl TryFrom<u64> for SysNo {
            /// The number is not a system call of the SVSM.
            type Error = u64;

            fn try_from(nr: u64) -> Result<Self, u64> {
                match nr {
                    $(n if n == $nr => Ok(Self::$name),)+
                    _ => Err(nr),
                }
            }
        }
    };
}

sys_numbers! {
    Read = 0,
    Write = 1,
    Close = 3,
    ExitGroup = 231,
    /// Queries the capabilities of the SVSM. Linux has no such call.
    SvsmCapabilities = NR_SVSM_BASE,
    /// TODO: Migrate these syscalls to Linux counterparts.
    SvsmExec = NR_SVSM_BASE + 1,
    SvsmOpen = NR_SVSM_BASE + 2,
    SvsmSeek = NR_SVSM_BASE + 3,
    SvsmTruncate = NR_SVSM_BASE + 4,
    SvsmUnlink = NR_SVSM_BASE + 5,
    SvsmOpendir = NR_SVSM_BASE + 6,
    SvsmReaddir = NR_SVSM_BASE + 7,
    SvsmMkdir = NR_SVSM_BASE + 8,
    SvsmRmdir = NR_SVSM_BASE + 9,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysno_try_from() {
        for &nr in SysNo::ALL {
            assert_eq!(SysNo::try_from(nr as u64), Ok(nr));
        }
        assert_eq!(SysNo::try_from(u64::MAX), Err(u64::MAX));
    }
}
