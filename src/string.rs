// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use core::array;
use core::fmt;
use core::mem::MaybeUninit;

extern crate alloc;
use alloc::string::String;

#[derive(Copy, Clone, Debug)]
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

    pub fn length(&self) -> usize {
        self.len
    }

    pub fn as_str(&self) -> String {
        let mut terminator = false;
        let s: String = self
            .data
            .iter()
            .filter(|c| {
                if terminator || **c == '\0' {
                    terminator = true;
                    false
                } else {
                    true
                }
            })
            .collect();
        s
    }
}

impl<const N: usize> From<[u8; N]> for FixedString<N> {
    fn from(arr: [u8; N]) -> FixedString<N> {
        let mut data: [MaybeUninit<char>; N] = array::from_fn(|_| MaybeUninit::uninit());
        let mut len = N;

        for (i, (d, val)) in data.iter_mut().zip(&arr).enumerate() {
            let val = *val;
            if val == 0 && len == N {
                len = i;
            }
            d.write(val as char);
        }

        let data = unsafe { *(data.as_ptr().cast::<[char; N]>()) };
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

impl<const N: usize> PartialEq<FixedString<N>> for FixedString<N> {
    fn eq(&self, other: &FixedString<N>) -> bool {
        if self.len != other.len {
            return false;
        }

        self.data
            .iter()
            .zip(&other.data)
            .take(self.len)
            .all(|(a, b)| *a == *b)
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

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::string::String;
    use core::fmt::Write;

    #[test]
    fn from_u8_array1() {
        let st = FixedString::from([b'a', b'b', b'c', b'd', b'z']);
        assert_eq!(st, "abcdz");
        assert_eq!(st.len, 5);
    }

    #[test]
    fn from_u8_array2() {
        let st = FixedString::from([b'a', b'b', b'c', b'\0', b'd', b'e']);
        assert_eq!(st, "abc");
        assert_eq!(st.len, 3);
    }

    #[test]
    fn from_ascii_str() {
        let ascii = " !\"£$%^*() some ASCII text";
        let fs = FixedString::<40>::from(ascii);
        assert_eq!(fs, ascii);
        assert_eq!(fs.as_str(), ascii);
    }

    #[test]
    fn from_ascii_str_embedded_term() {
        let ascii = " !\"£\0$%^*() some ASCII text";
        let ascii_expected = " !\"£";
        let fs = FixedString::<40>::from(ascii);
        assert_eq!(fs, ascii);
        assert_eq!(fs.as_str(), ascii_expected);
    }

    #[test]
    fn display() {
        let mut buf = String::new();
        let st = FixedString::from([b's', b'v', b's', b'm', b'\0', b'x', b'y']);
        write!(&mut buf, "{}", st).unwrap();
        assert_eq!(buf.as_str(), "svsm");
    }
}
