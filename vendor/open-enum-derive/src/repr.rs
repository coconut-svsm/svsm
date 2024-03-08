// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::discriminant::Discriminant;
use proc_macro2::{Ident, TokenStream};
use quote::ToTokens;
use std::ops::RangeInclusive;
use syn::{parse::Parse, Error};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Repr {
    I8,
    U8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    Usize,
    Isize,
    #[cfg(feature = "repr_c")]
    C,
}

fn range_contains(x: &RangeInclusive<i128>, y: &RangeInclusive<i128>) -> bool {
    x.contains(y.start()) && x.contains(y.end())
}

impl Repr {
    const REPR_RANGES: &'static [(Repr, RangeInclusive<i128>)] = &[
        (Repr::I8, (i8::MIN as i128)..=(i8::MAX as i128)),
        (Repr::U8, (u8::MIN as i128)..=(u8::MAX as i128)),
        (Repr::I16, (i16::MIN as i128)..=(i16::MAX as i128)),
        (Repr::U16, (u16::MIN as i128)..=(u16::MAX as i128)),
        (Repr::I32, (i32::MIN as i128)..=(i32::MAX as i128)),
        (Repr::U32, (u32::MIN as i128)..=(u32::MAX as i128)),
        (Repr::I64, (i64::MIN as i128)..=(i64::MAX as i128)),
        (Repr::U64, (u64::MIN as i128)..=(u64::MAX as i128)),
        (Repr::Isize, (isize::MIN as i128)..=(isize::MAX as i128)),
        (Repr::Usize, (usize::MIN as i128)..=(usize::MAX as i128)),
    ];

    /// Finds the smallest repr that can fit this range, if any.
    fn smallest_fitting_repr(range: RangeInclusive<i128>) -> Option<Self> {
        // TODO: perhaps check this logic matches current rustc behavior?
        for (repr, repr_range) in Self::REPR_RANGES {
            if range_contains(repr_range, &range) {
                return Some(*repr);
            }
        }
        None
    }

    fn name(self) -> &'static str {
        match self {
            Repr::I8 => "i8",
            Repr::U8 => "u8",
            Repr::U16 => "u16",
            Repr::I16 => "i16",
            Repr::U32 => "u32",
            Repr::I32 => "i32",
            Repr::U64 => "u64",
            Repr::I64 => "i64",
            Repr::Usize => "usize",
            Repr::Isize => "isize",
            #[cfg(feature = "repr_c")]
            Repr::C => "C",
        }
    }
}

impl ToTokens for Repr {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend([match self {
            // Technically speaking, #[repr(C)] on an enum isn't always `c_int`,
            // but those who care can fix it if they need.
            #[cfg(feature = "repr_c")]
            Repr::C => quote!(::open_enum::__private::c_int),
            x => x.name().parse::<TokenStream>().unwrap(),
        }])
    }
}

impl Parse for Repr {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let ident: Ident = input.parse()?;
        Ok(match ident.to_string().as_str() {
            "i8" => Repr::I8,
            "u8" => Repr::U8,
            "i16" => Repr::I16,
            "u16" => Repr::U16,
            "i32" => Repr::I32,
            "u32" => Repr::U32,
            "i64" => Repr::I64,
            "u64" => Repr::U64,
            "usize" => Repr::Usize,
            "isize" => Repr::Isize,
            #[cfg(feature = "repr_c")]
            "C" => Repr::C,
            #[cfg(not(feature = "repr_c"))]
            "C" => {
                return Err(Error::new(
                    ident.span(),
                    "#[repr(C)] requires either the `std` or `libc_` feature",
                ))
            }
            _ => {
                return Err(Error::new(
                    ident.span(),
                    format!("unsupported repr `{ident}`"),
                ))
            }
        })
    }
}

/// Figure out what the internal representation of the enum should be given its variants.
///
/// If we don't have sufficient info to auto-shrink the internal repr, fallback to isize.
pub fn autodetect_inner_repr<'a>(variants: impl Iterator<Item = &'a Discriminant>) -> Repr {
    let mut variants = variants.peekable();
    if variants.peek().is_none() {
        // TODO: maybe use the unit type for a fieldless open enum without a #[repr]?
        return Repr::Isize;
    }
    let mut min = i128::MAX;
    let mut max = i128::MIN;
    for value in variants {
        match value {
            &Discriminant::Literal(value) => {
                min = min.min(value);
                max = max.max(value);
            }
            Discriminant::Nonliteral { .. } => {
                // No way to do fancy sizing here, fall back to isize.
                return Repr::Isize;
            }
        }
    }
    Repr::smallest_fitting_repr(min..=max).unwrap_or(Repr::Isize)
}
