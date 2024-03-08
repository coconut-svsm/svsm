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

use std::collections::HashSet;

use proc_macro2::{Ident, Span};
use quote::ToTokens;
use syn::{parse::Parse, Error, Token, Visibility};

pub struct Config {
    pub allow_alias: bool,
    pub repr_visibility: Visibility,
}

impl Parse for Config {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut out = Self {
            allow_alias: false,
            repr_visibility: Visibility::Public(syn::VisPublic {
                pub_token: Token![pub](Span::call_site()),
            }),
        };
        let mut seen_names = HashSet::new();
        while !input.is_empty() {
            let name: Ident = input.parse()?;
            let name_string = name.to_token_stream().to_string();
            let has_value = input.peek(Token![=]);
            if has_value {
                let _eq_token: Token![=] = input.parse()?;
            }
            match name_string.as_str() {
                "allow_alias" => {
                    if has_value {
                        let allow_alias: syn::LitBool = input.parse()?;
                        out.allow_alias = allow_alias.value;
                    } else {
                        out.allow_alias = true;
                    }
                }
                name_str @ "inner_vis" if !has_value => {
                    return Err(Error::new(
                        name.span(),
                        &format!("Option `{name_str}` requires a value"),
                    ))
                }
                "inner_vis" => {
                    out.repr_visibility = input.parse()?;
                    if matches!(out.repr_visibility, syn::Visibility::Inherited) {
                        return Err(input.error("Expected visibility"));
                    }
                }
                unknown_name => {
                    return Err(Error::new(
                        name.span(),
                        &format!("Unknown option `{unknown_name}`"),
                    ));
                }
            }
            if !input.is_empty() {
                let _comma: Token![,] = input.parse()?;
            }
            if !seen_names.insert(name_string) {
                return Err(Error::new(
                    name.span(),
                    &format!(
                        "Option `{name}` listed more than once",
                        name = name.to_token_stream()
                    ),
                ));
            }
        }
        Ok(out)
    }
}
