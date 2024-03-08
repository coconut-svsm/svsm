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

use proc_macro2::{Literal, TokenStream};
use quote::{quote, ToTokens};
use syn::Expr;

#[derive(Clone)]
pub enum Discriminant {
    Literal(i128),
    Nonliteral { base: Box<Expr>, offset: u32 },
}

impl Discriminant {
    pub fn new(discriminant_expr: Expr) -> syn::Result<Self> {
        // Positive literal int
        if let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(lit),
            ..
        }) = &discriminant_expr
        {
            return Ok(Discriminant::Literal(lit.base10_parse()?));
        }

        // Negative literal int
        if let syn::Expr::Unary(syn::ExprUnary {
            op: syn::UnOp::Neg(_),
            expr,
            ..
        }) = &discriminant_expr
        {
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(lit),
                ..
            }) = &**expr
            {
                return Ok(Discriminant::Literal(-lit.base10_parse()?));
            }
        }

        // Nonliteral expression
        Ok(Discriminant::Nonliteral {
            base: Box::new(discriminant_expr),
            offset: 0,
        })
    }

    pub fn next_value(self) -> Option<Self> {
        Some(match self {
            Discriminant::Literal(val) => Discriminant::Literal(val.checked_add(1)?),
            Discriminant::Nonliteral { base, offset } => Discriminant::Nonliteral {
                base,
                offset: offset.checked_add(1)?,
            },
        })
    }
}

impl ToTokens for Discriminant {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(match self {
            Discriminant::Literal(value) => Literal::i128_unsuffixed(*value).into_token_stream(),
            Discriminant::Nonliteral { base, offset } => {
                if *offset == 0 {
                    base.into_token_stream()
                } else {
                    let offset = Literal::u32_unsuffixed(*offset);
                    quote!(#base + #offset)
                }
            }
        })
    }
}
