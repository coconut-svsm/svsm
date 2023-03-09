// SPDX-License-Identifier: (GPL-2.0-or-later OR MIT)
//
// Copyright (c) 2022 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>
//
// vim: ts=4 sw=4 et

use core::fmt;
use core::mem::MaybeUninit;

pub struct FixedString<const T: usize> {
    len: usize,
    data: [char; T],
}

impl<const T: usize> FixedString<T> {
    pub const fn new() -> Self {
        FixedString {
            len: 0,
            data: ['\0'; T],
        }
    }

    pub fn push(&mut self, c: char) {
        let l = self.len;

        if l > 0 && self.data[l - 1] == '\0' {
            return;
        }

        self.data[l] = c;
        self.len += 1;
    }
}

impl<const N: usize> From<[u8; N]> for FixedString<N> {
    fn from(arr: [u8; N]) -> FixedString<N> {
        let mut data = MaybeUninit::<char>::uninit_array::<N>();
        let mut len = N;

        for (i, (d, val)) in data.iter_mut().zip(&arr).enumerate() {
            let val = *val;
            if val == 0 && len == N {
                len = i;
            }
            d.write(val as char);
        }

        let data = unsafe { MaybeUninit::array_assume_init(data) };
        FixedString { data, len }
    }
}

impl<const N: usize> From<&str> for FixedString<N> {
    fn from(st: &str) -> FixedString<N> {
        let mut fs = FixedString::new();
        for c in st.chars().take(N) {
            fs.data[fs.len] = c;
            fs.len += 1;
        }
        fs
    }
}

impl<const N: usize> PartialEq<&str> for FixedString<N> {
    fn eq(&self, other: &&str) -> bool {
        for (i, c) in other.chars().enumerate() {
            if i >= N {
                return false;
            }
            if self.data[i] != c {
                return false;
            }
        }
        true
    }
}

impl<const T: usize> fmt::Display for FixedString<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for b in self.data.iter().take(self.len) {
            write!(f, "{}", *b)?;
        }
        Ok(())
    }
}
