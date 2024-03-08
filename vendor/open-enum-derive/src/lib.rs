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

extern crate proc_macro;

mod config;
mod discriminant;
mod repr;

use config::Config;

use discriminant::Discriminant;
use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, ToTokens};
use repr::Repr;
use std::collections::HashSet;
use syn::{
    parse_macro_input, punctuated::Punctuated, spanned::Spanned, Error, Ident, ItemEnum, Visibility,
};

/// Sets the span for every token tree in the token stream
fn set_token_stream_span(tokens: TokenStream, span: Span) -> TokenStream {
    tokens
        .into_iter()
        .map(|mut tt| {
            tt.set_span(span);
            tt
        })
        .collect()
}

/// Checks that there are no duplicate discriminant values. If all variants are literals, return an `Err` so we can have
/// more clear error messages. Otherwise, emit a static check that ensures no duplicates.
fn check_no_alias<'a>(
    enum_: &ItemEnum,
    variants: impl Iterator<Item = (&'a Ident, &'a Discriminant, Span)> + Clone,
) -> syn::Result<TokenStream> {
    // If they're all literals, we can give better error messages by checking at proc macro time.
    let mut values: HashSet<i128> = HashSet::new();
    for (_, variant, span) in variants {
        if let &Discriminant::Literal(value) = variant {
            if !values.insert(value) {
                return Err(Error::new(
                    span,
                    &format!("discriminant value `{value}` assigned more than once"),
                ));
            }
        } else {
            let mut checking_enum = syn::ItemEnum {
                ident: format_ident!("_Check{}", enum_.ident),
                vis: Visibility::Inherited,
                ..enum_.clone()
            };
            checking_enum.attrs.retain(|attr| {
                matches!(
                    attr.path.to_token_stream().to_string().as_str(),
                    "repr" | "allow" | "warn" | "deny" | "forbid"
                )
            });
            return Ok(quote!(
                #[allow(dead_code)]
                #checking_enum
            ));
        }
    }
    Ok(TokenStream::default())
}

fn emit_debug_impl<'a>(
    ident: &Ident,
    variants: impl Iterator<Item = &'a Ident> + Clone,
) -> TokenStream {
    quote!(impl ::core::fmt::Debug for #ident {
        fn fmt(&self, fmt: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            #![allow(unreachable_patterns)]
            let s = match *self {
                #( Self::#variants => stringify!(#variants), )*
                _ => {
                    return fmt.debug_tuple(stringify!(#ident)).field(&self.0).finish();
                }
            };
            fmt.pad(s)
        }
    })
}

fn path_matches_prelude_derive(
    got_path: &syn::Path,
    expected_path_after_std: &[&'static str],
) -> bool {
    let &[a, b] = expected_path_after_std else {
        unimplemented!("checking against stdlib paths with != 2 parts");
    };
    let segments: Vec<&syn::PathSegment> = got_path.segments.iter().collect();
    if segments
        .iter()
        .any(|segment| !matches!(segment.arguments, syn::PathArguments::None))
    {
        return false;
    }
    match &segments[..] {
        // `core::fmt::Debug` or `some_crate::module::Name`
        &[maybe_core_or_std, maybe_a, maybe_b] => {
            (maybe_core_or_std.ident == "core" || maybe_core_or_std.ident == "std")
                && maybe_a.ident == a
                && maybe_b.ident == b
        }
        // `fmt::Debug` or `module::Name`
        &[maybe_a, maybe_b] => {
            maybe_a.ident == a && maybe_b.ident == b && got_path.leading_colon.is_none()
        }
        // `Debug` or `Name``
        &[maybe_b] => maybe_b.ident == b && got_path.leading_colon.is_none(),
        _ => false,
    }
}

fn open_enum_impl(
    enum_: ItemEnum,
    Config {
        allow_alias,
        repr_visibility,
    }: Config,
) -> Result<TokenStream, Error> {
    // Does the enum define a `#[repr()]`?
    let mut struct_attrs: Vec<TokenStream> = Vec::with_capacity(enum_.attrs.len() + 5);
    struct_attrs.push(quote!(#[allow(clippy::exhaustive_structs)]));

    if !enum_.generics.params.is_empty() {
        return Err(Error::new(enum_.generics.span(), "enum cannot be generic"));
    }
    let mut variants = Vec::with_capacity(enum_.variants.len());
    let mut last_field = Discriminant::Literal(-1);
    for variant in &enum_.variants {
        if !matches!(variant.fields, syn::Fields::Unit) {
            return Err(Error::new(variant.span(), "enum cannot contain fields"));
        }

        let (value, value_span) = if let Some((_, discriminant)) = &variant.discriminant {
            let span = discriminant.span();
            (Discriminant::new(discriminant.clone())?, span)
        } else {
            last_field = last_field
                .next_value()
                .ok_or_else(|| Error::new(variant.span(), "enum discriminant overflowed"))?;
            (last_field.clone(), variant.ident.span())
        };
        last_field = value.clone();
        variants.push((&variant.ident, value, value_span, &variant.attrs))
    }

    let mut impl_attrs: Vec<TokenStream> = vec![quote!(#[allow(non_upper_case_globals)])];
    let mut explicit_repr: Option<Repr> = None;

    // To make `match` seamless, derive(PartialEq, Eq) if they aren't already.
    let mut extra_derives = vec![quote!(::core::cmp::PartialEq), quote!(::core::cmp::Eq)];

    let mut make_custom_debug_impl = false;
    for attr in &enum_.attrs {
        let mut include_in_struct = true;
        // Turns out `is_ident` does a `to_string` every time
        match attr.path.to_token_stream().to_string().as_str() {
            "derive" => {
                if let Ok(derive_paths) =
                    attr.parse_args_with(Punctuated::<syn::Path, syn::Token![,]>::parse_terminated)
                {
                    for derive in &derive_paths {
                        // These derives are treated specially
                        const PARTIAL_EQ_PATH: &[&str] = &["cmp", "PartialEq"];
                        const EQ_PATH: &[&str] = &["cmp", "Eq"];
                        const DEBUG_PATH: &[&str] = &["fmt", "Debug"];

                        if path_matches_prelude_derive(derive, PARTIAL_EQ_PATH)
                            || path_matches_prelude_derive(derive, EQ_PATH)
                        {
                            // This derive is always included, exclude it.
                            continue;
                        }
                        if path_matches_prelude_derive(derive, DEBUG_PATH) {
                            if !allow_alias {
                                make_custom_debug_impl = true;
                                // Don't include this derive since we're generating a special one.
                                continue;
                            }
                        }
                        extra_derives.push(derive.to_token_stream());
                    }
                    include_in_struct = false;
                }
            }
            // Copy linting attribute to the impl.
            "allow" | "warn" | "deny" | "forbid" => impl_attrs.push(attr.to_token_stream()),
            "repr" => {
                assert!(explicit_repr.is_none(), "duplicate explicit repr");
                explicit_repr = Some(attr.parse_args()?);
                include_in_struct = false;
            }
            "non_exhaustive" => {
                // technically it's exhaustive if the enum covers the full integer range
                return Err(Error::new(attr.path.span(), "`non_exhaustive` cannot be applied to an open enum; it is already non-exhaustive"));
            }
            _ => {}
        }
        if include_in_struct {
            struct_attrs.push(attr.to_token_stream());
        }
    }

    // The proper repr to type-check against
    let typecheck_repr: Repr = explicit_repr.unwrap_or(Repr::Isize);

    // The actual representation of the value.
    let inner_repr = match explicit_repr {
        Some(explicit_repr) => {
            // If there is an explicit repr, emit #[repr(transparent)].
            struct_attrs.push(quote!(#[repr(transparent)]));
            explicit_repr
        }
        None => {
            // If there isn't an explicit repr, determine an appropriate sized integer that will fit.
            // Interpret all discriminant expressions as isize.
            repr::autodetect_inner_repr(variants.iter().map(|v| &v.1))
        }
    };

    if !extra_derives.is_empty() {
        struct_attrs.push(quote!(#[derive(#(#extra_derives),*)]));
    }

    let alias_check = if allow_alias {
        TokenStream::default()
    } else {
        check_no_alias(&enum_, variants.iter().map(|(i, v, s, _)| (*i, v, *s)))?
    };

    let syn::ItemEnum { ident, vis, .. } = enum_;

    let debug_impl = if make_custom_debug_impl {
        emit_debug_impl(&ident, variants.iter().map(|(i, _, _, _)| *i))
    } else {
        TokenStream::default()
    };

    let fields = variants
        .into_iter()
        .map(|(name, value, value_span, attrs)| {
            let mut value = value.into_token_stream();
            value = set_token_stream_span(value, value_span);
            let inner = if typecheck_repr == inner_repr {
                value
            } else {
                quote!(::core::convert::identity::<#typecheck_repr>(#value) as #inner_repr)
            };
            quote!(
                #(#attrs)*
                pub const #name: #ident = #ident(#inner);
            )
        });

    Ok(quote! {
        #(#struct_attrs)*
        #vis struct #ident(#repr_visibility #inner_repr);

        #(#impl_attrs)*
        impl #ident {
            #(
                #fields
            )*
        }
        #debug_impl
        #alias_check
    })
}

#[proc_macro_attribute]
pub fn open_enum(
    attrs: proc_macro::TokenStream,
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let enum_ = parse_macro_input!(input as syn::ItemEnum);
    let config = parse_macro_input!(attrs as Config);
    open_enum_impl(enum_, config)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_matches_stdlib_derive() {
        const DEBUG_PATH: &[&str] = &["fmt", "Debug"];

        for success_case in [
            "::core::fmt::Debug",
            "::std::fmt::Debug",
            "core::fmt::Debug",
            "std::fmt::Debug",
            "fmt::Debug",
            "Debug",
        ] {
            assert!(
                path_matches_prelude_derive(&syn::parse_str(success_case).unwrap(), DEBUG_PATH),
                "{success_case}"
            );
        }

        for fail_case in [
            "::fmt::Debug",
            "::Debug",
            "zerocopy::AsBytes",
            "::zerocopy::AsBytes",
            "PartialEq",
            "core::cmp::Eq",
        ] {
            assert!(
                !path_matches_prelude_derive(&syn::parse_str(fail_case).unwrap(), DEBUG_PATH),
                "{fail_case}"
            );
        }
    }
}
