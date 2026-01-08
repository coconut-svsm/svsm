// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2025 Red Hat, Inc.
//
// Author: Luigi Leonardi <leonardi@redhat.com>

extern crate proc_macro;
use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn verus_verify(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[proc_macro_attribute]
pub fn verus_spec(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[proc_macro]
pub fn verus(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    input
}

#[proc_macro]
pub fn proof(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}

#[proc_macro]
pub fn proof_decl(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}

#[proc_macro]
pub fn proof_with(_input: TokenStream) -> TokenStream {
    TokenStream::new()
}
