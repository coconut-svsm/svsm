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

//! Rust enums are _closed_, meaning that the integer value distinguishing an enum, its _discriminant_,
//! must be one of the variants listed. If the integer value isn't one of those discriminants, it
//! is considered immediate [undefined behavior][ub]. This is true for enums with and without fields.
//!
//! This has some disadvantages:
//! - in constrained environments, closed enums can require premature runtime checks when using
//!   `TryFrom` to convert from an integer. This is doubly true if the value will be checked again
//!   at a later point, such as with a C library.
//! - an outdated binary using an enum won't preserve the value of an unknown field when reserializing
//!   data without an extra `Unrecognized` value making the type more expensive than an integer.
//! - it can introduce Undefined Behavior at unexpected times if the author is unfamiliar with
//!   the [rules of writing `unsafe` Rust][nomicon].
//!
//! In constrast, C++ [scoped enumerations][cpp-scoped-enum] are _open_, meaning that the enum is a
//! strongly-typed integer that could hold any value, though with a scoped set of well-known values.
//!
//! The _open enum_ pattern lets you have this in Rust. With a [newtype][newtype] and associated constants,
//! the [open_enum][open_enum] macro turns this enum declaration:
//!
//! ```
//! # use open_enum::open_enum;
//! #[open_enum]
//! enum Color {
//!     Red,
//!     Green,
//!     Blue,
//!     Orange,
//!     Black,
//! }
//! ```
//!
//! into a tuple struct with associated constants:
//!
//! ```
//! #[derive(PartialEq, Eq)]  // In order to work in `match`.
//! struct Color(pub i8);  // Automatic integer type, can be specified with #[repr]
//!
//! impl Color {
//!     pub const Red: Self = Color(0);
//!     pub const Green: Self = Color(1);
//!     pub const Blue: Self = Color(2);
//!     pub const Orange: Self = Color(3);
//!     pub const Black: Self = Color(4);
//! }
//! ```
//!
//! There are clear readability benefits to using field-less `enum`s to represent enumerated integer data.
//! It provides more type safety than a raw integer, the `enum` syntax is consise, and it provides a
//! set of constants grouped under a type that can have methods.
//!
//! # Usage
//! Usage is similar to regular `enum`s, but with some key differences.
//!
//! ```
//! # use open_enum::open_enum;
//! # #[open_enum]
//! # #[derive(Debug)]
//! # enum Color {
//! #     Red,
//! #     Green,
//! #     Blue,
//! #     Orange,
//! #     Black,
//! # }
//! // Construct an open enum with the same `EnumName::VariantName` syntax.
//! let mut blood_of_angry_men = Color::Red;
//!
//! // Access the integer value with `.0`.
//! // This does not work: `Color::Red as u8`.
//! assert_eq!(blood_of_angry_men.0, 0);
//!
//! // Construct an open enum with an arbitrary integer value like any tuple struct.
//! let dark_of_ages_past = Color(4);
//!
//! // open enums always implement `PartialEq` and `Eq`, unlike regular enums.
//! assert_eq!(dark_of_ages_past, Color::Black);
//!
//! // This is outside of the known colors - but that's OK!
//! let this_is_fine = Color(10);
//!
//! // A match is always non-exhaustive - requiring a wildcard branch.
//! match this_is_fine {
//!     Color::Red => panic!("a world about to dawn"),
//!     Color::Green => panic!("grass"),
//!     Color::Blue => panic!("蒼: not to be confused with 緑"),
//!     Color::Orange => panic!("fun fact: the fruit name came first"),
//!     Color::Black => panic!("the night that ends at last"),
//!     // Wildcard branch, if we don't recognize the value. `x =>` also works.
//!     Color(value) => assert_eq!(value, 10),
//! }
//!
//! // Unlike a regular enum, you can pass the discriminant as a reference.
//! fn increment(x: &mut i8) {
//!     *x += 1;
//! }
//!
//! increment(&mut blood_of_angry_men.0);
//! // These aren't men, they're skinks!
//! assert_eq!(blood_of_angry_men, Color::Green);
//!
//! ```
//!
//! ## Integer type
//! `open_enum` will automatically determine an appropriately sized integer[^its-all-isize] to
//! represent the enum, if possible[^nonliterals-are-hard]. To choose a specific representation, it's the same
//! as a regular `enum`: add `#[repr(type)]`.
//! You can also specify `#[repr(C)]` to choose a C `int`.[^repr-c-feature][^repr-c-weird]
//!
//! If you specify an explicit `repr`, the output struct will be `#[repr(transparent)]`.
//!
//! ```
//! # use open_enum::open_enum;
//! #[open_enum]
//! #[repr(i16)]
//! #[derive(Debug)]
//! enum Fruit {
//!     Apple,
//!     Banana,
//!     Kumquat,
//!     Orange,
//! }
//!
//! assert_eq!(Fruit::Banana.0, 1i16);
//! assert_eq!(Fruit::Kumquat, Fruit(2));
//!
//! ```
//!  <div class="example-wrap" style="display:inline-block"><pre class="compile_fail" style="white-space:normal;font:inherit;">
//!
//!  **Warning**: `open_enum` may change the automatic integer representation for a given enum
//! in a future version with a minor version bump - it is not considered a breaking change.
//! Do not depend on this type remaining stable - use an explicit `#[repr]` for stability.
//!
//! </pre></div>
//!
//! [^its-all-isize]: Like regular `enum`s, the declared discriminant for enums without an explicit `repr`
//! is interpreted as an `isize` regardless of the automatic storage type chosen.
//!
//! [^nonliterals-are-hard]: This optimization fails if the `enum` declares a non-literal constant expression
//! as one of its discriminant values, and falls back to `isize`. To avoid this, specify an explicit `repr`.
//!
//! [^repr-c-weird]: Note that this might not actually be the correct default `enum` size for C on all platforms,
//!                  since the [compiler could choose something smaller than `int`](https://stackoverflow.com/a/366026).
//!
//! [^repr-c-feature]: This requires either the `std` or `libc_` feature (note the underscore)
//!
//! ## Aliasing variants
//! Regular `enum`s cannot have multiple variants with the same discriminant.
//! However, since `open_enum` produces associated constants, multiple
//! names can represent the same integer value. By default, `open_enum`
//! rejects aliasing variants, but it can be allowed with the `allow_alias` option:
//!
//! ```
//! # use open_enum::open_enum;
//! #[open_enum(allow_alias)]
//! #[derive(Debug)]
//! enum Character {
//!     Viola = 0,
//!     Cesario = 0,
//!     Sebastian,
//!     Orsino,
//!     Olivia,
//!     Malvolio,
//! }
//!
//! assert_eq!(Character::Viola, Character::Cesario);
//!
//! ```
//!
//!
//!
//! # Custom debug implementation
//! `open_enum` will generate a debug implementation that mirrors the standard `#[derive(Debug)]` for normal Rust enums
//! by printing the name of the variant rather than the value contained, if the value is a named variant.
//!
//! However, if an enum has `#[open_enum(allow_alias)]` specified, the debug representation will be the numeric value only.
//!
//! For example, this given enum,
//! ```
//! # use open_enum::open_enum;
//! #[open_enum]
//! #[derive(Debug)]
//! enum Fruit {
//!     Apple,
//!     Pear,
//!     Banana,
//!     Blueberry = 5,
//!     Raspberry,
//! }
//! ```
//!
//! will have the following debug implementation emitted:
//! ```
//! # use open_enum::open_enum;
//! # #[open_enum]
//! # enum Fruit {
//! #     Apple,
//! #     Pear,
//! #     Banana,
//! #     Blueberry = 5,
//! #     Raspberry,
//! # }
//! # impl ::core::fmt::Debug for Fruit {
//! fn fmt(&self, fmt: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
//!         #![allow(unreachable_patterns)]
//!         let s = match *self {
//!             Self::Apple => stringify!(Apple),
//!             Self::Pear => stringify!(Pear),
//!             Self::Banana => stringify!(Banana),
//!             Self::Blueberry => stringify!(Blueberry),
//!             Self::Raspberry => stringify!(Raspberry),
//!             _ => {
//!                 return fmt.debug_tuple(stringify!(Fruit)).field(&self.0).finish();
//!             }
//!         };
//!         fmt.pad(s)
//!     }
//! # }
//! ```
//!
//! # Compared with `#[non_exhuastive]`
//! The [`non_exhaustive`][non-exhaustive] attribute indicates that a type or variant
//! may have more fields or variants added in the future. When applied to an `enum` (not its variants),
//! it requires that foreign crates provide a wildcard arm when `match`ing.
//! Since open enums are inherently non-exhaustive[^mostly-non-exhaustive], this attribute is incompatible
//! with `open_enum`. Unlike `non_exhaustive`, open enums also require a wildcard branch on `match`es in
//! the defining crate.
//!
//! [^mostly-non-exhaustive]: Unless the enum defines a variant for every value of its underlying integer.
//!
//! # Disadvantages of open enums
//! - The kind listed in the source code, an `enum`, is not the same as the actual output, a `struct`,
//!   which could be confusing or hard to debug, since its usage is similar, but not exactly the same.
//! - No niche optimization: `Option<Color>` is 1 byte as a regular enum,
//!   but 2 bytes as an open enum.
//! - No pattern-matching assistance in rust-analyzer.
//! - You must have a wildcard case when pattern matching.
//! - `match`es that exist elsewhere won't break when you add a new variant,
//!   similar to `#[non_exhaustive]`. However, it also means you may accidentally
//!   forget to fill out a branch arm.
//!
//!
//! [cpp-scoped-enum]: https://en.cppreference.com/w/cpp/language/enum#Scoped_enumerations
//! [nomicon]: https://doc.rust-lang.org/nomicon/
//! [non-exhaustive]: https://doc.rust-lang.org/reference/attributes/type_system.html#the-non_exhaustive-attribute
//! [ub]: https://doc.rust-lang.org/reference/behavior-considered-undefined.html

#![no_std]

/// Constructs an *open* enum from a Rust enum definition,
/// allowing it to represent more than just its listed variants.
///
/// See the [crate documentation](crate) for more details.
///
/// # Example
/// ```
/// # use open_enum::open_enum;
/// #[open_enum]
/// #[derive(Debug)]
/// enum Color {
///     Red,
///     Green,
///     Blue,
///     Orange,
///     Black,
/// }
///
/// assert_eq!(Color::Red, Color(0));
/// assert_eq!(Color(10).0, 10);
/// ```
///
/// # Options
/// - `allow_alias[ = $bool]`: default `false`. Allows duplicate discriminant values for variants.
/// - `inner_vis = $vis`: default `pub`. Specifies the visibility of the inner integer.
///
/// # Integer type
/// `open_enum` configures the discriminant type by intercepting a `repr` attribute on the enum.
/// If done, the open enum is `#[repr(transparent)]` over the provided integer type.
/// Otherwise, variant discriminants are interpreted as `isize` and an automatic integer type chosen.
///
/// # `PartialEq`/`Eq`
/// Open enums implement `PartialEq` and `Eq` in order to work in a `match` statement.
pub use open_enum_derive::open_enum;

/// Utility items only to be used by macros. Do not expect API stability.
#[doc(hidden)]
pub mod __private {
    #[cfg(all(feature = "libc", not(feature = "std")))]
    pub use libc::c_int;

    #[cfg(feature = "std")]
    extern crate std;

    #[cfg(feature = "std")]
    pub use std::os::raw::c_int;
}
