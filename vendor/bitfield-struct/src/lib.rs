// Generate docs from readme
#![doc = include_str!("../README.md")]
#![warn(clippy::unwrap_used)]

use proc_macro as pc;
use proc_macro2::{Ident, Span, TokenStream};
use quote::{format_ident, quote, ToTokens};
use std::stringify;
use syn::parse::{Parse, ParseStream};
use syn::spanned::Spanned;
use syn::Token;

/// Creates a bitfield for this struct.
///
/// The arguments first, have to begin with the underlying type of the bitfield:
/// For example: `#[bitfield(u64)]`.
///
/// It can contain an extra `debug` argument for disabling the `Debug` trait
/// generation (`#[bitfield(u64, debug = false)]`).
///
/// Parameters of the `bitfield` attribute:
/// - the bitfield type
/// - `debug` to disable the `Debug` trait generation
/// - `default` to disable the `Default` trait generation
/// - `order` to specify the bit order (Lsb, Msb)
///
/// Parameters of the `bits` attribute (for fields):
/// - the number of bits
/// - `access` to specify the access mode (RW, RO, WO, None)
/// - `default` to set a default value
/// - `into` to specify a conversion function from the field type to the bitfield type
/// - `from` to specify a conversion function from the bitfield type to the field type
#[proc_macro_attribute]
pub fn bitfield(args: pc::TokenStream, input: pc::TokenStream) -> pc::TokenStream {
    match bitfield_inner(args.into(), input.into()) {
        Ok(result) => result.into(),
        Err(e) => e.into_compile_error().into(),
    }
}

fn bitfield_inner(args: TokenStream, input: TokenStream) -> syn::Result<TokenStream> {
    let input = syn::parse2::<syn::ItemStruct>(input)?;
    let Params {
        ty,
        bits,
        debug,
        default,
        order,
    } = syn::parse2::<Params>(args)?;

    let span = input.fields.span();
    let name = input.ident;
    let vis = input.vis;
    let attrs: TokenStream = input.attrs.iter().map(ToTokens::to_token_stream).collect();

    let syn::Fields::Named(fields) = input.fields else {
        return Err(syn::Error::new(span, "only named fields are supported"));
    };

    let mut offset = 0;
    let mut members = Vec::with_capacity(fields.named.len());
    for field in fields.named {
        let f = Member::new(ty.clone(), bits, field, offset, order)?;
        offset += f.bits;
        members.push(f);
    }

    if offset < bits {
        return Err(syn::Error::new(
            span,
            format!(
                "The bitfiled size ({bits} bits) has to be equal to the sum of its members ({offset} bits)!. \
                You might have to add padding (a {} bits large member prefixed with \"_\").",
                bits - offset
            ),
        ));
    }
    if offset > bits {
        return Err(syn::Error::new(
            span,
            format!(
                "The size of the members ({offset} bits) is larger than the type ({bits} bits)!."
            ),
        ));
    }

    let debug_impl = if debug {
        let debug_fields = members.iter().map(Member::debug);
        quote! {
            impl core::fmt::Debug for #name {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.debug_struct(stringify!(#name))
                        #( #debug_fields )*
                        .finish()
                }
            }
        }
    } else {
        TokenStream::default()
    };

    let defaults = members.iter().map(Member::default);

    let default_impl = if default {
        quote! {
            impl Default for #name {
                fn default() -> Self {
                    Self::new()
                }
            }
        }
    } else {
        TokenStream::new()
    };

    Ok(quote! {
        #attrs
        #[derive(Copy, Clone)]
        #[repr(transparent)]
        #vis struct #name(#ty);

        impl #name {
            /// Creates a new default initialized bitfield.
            #vis const fn new() -> Self {
                let mut this = Self(0);
                #( #defaults )*
                this
            }

            #( #members )*
        }

        #default_impl

        impl From<#ty> for #name {
            fn from(v: #ty) -> Self {
                Self(v)
            }
        }
        impl From<#name> for #ty {
            fn from(v: #name) -> #ty {
                v.0
            }
        }

        #debug_impl
    })
}

/// Represents a member where accessor functions should be generated for.
struct Member {
    offset: usize,
    bits: usize,
    base_ty: syn::Type,
    default: TokenStream,
    inner: Option<MemberInner>,
}

struct MemberInner {
    ident: syn::Ident,
    ty: syn::Type,
    attrs: Vec<syn::Attribute>,
    vis: syn::Visibility,
    into: TokenStream,
    from: TokenStream,
}

impl Member {
    fn new(
        base_ty: syn::Type,
        base_bits: usize,
        f: syn::Field,
        offset: usize,
        order: Order,
    ) -> syn::Result<Self> {
        let span = f.span();

        let syn::Field {
            mut attrs,
            vis,
            ident,
            ty,
            ..
        } = f;

        let ident = ident.ok_or_else(|| syn::Error::new(span, "Not supported"))?;
        let ignore = ident.to_string().starts_with('_');

        let Field {
            bits,
            ty,
            mut default,
            into,
            from,
            access,
        } = parse_field(&base_ty, &attrs, &ty, ignore)?;

        let ignore = ignore || access == Access::None;

        if bits > 0 && !ignore {
            // overflow check
            if offset + bits > base_bits {
                return Err(syn::Error::new(
                    ty.span(),
                    "The total size of the members is too large!",
                ));
            };

            // clear conversion expr if not needed
            let (from, into) = match access {
                Access::ReadWrite => (from, into),
                Access::ReadOnly => (from, quote!()),
                Access::WriteOnly => (quote!(), into),
                Access::None => (quote!(), quote!()),
            };

            // compute the offset
            let offset = if order == Order::Lsb {
                offset
            } else {
                base_bits - offset - bits
            };

            // auto-conversion from zero
            if default.is_empty() {
                if !from.is_empty() {
                    default = quote!({ let this = 0; #from });
                } else {
                    default = quote!(0);
                }
            }

            // remove our attribute
            attrs.retain(|a| !a.path().is_ident("bits"));

            Ok(Self {
                offset,
                bits,
                base_ty,
                default,
                inner: Some(MemberInner {
                    ident,
                    ty,
                    attrs,
                    vis,
                    into,
                    from,
                }),
            })
        } else {
            if default.is_empty() {
                default = quote!(0);
            }

            Ok(Self {
                offset,
                bits,
                base_ty,
                default,
                inner: None,
            })
        }
    }

    fn debug(&self) -> TokenStream {
        if let Some(inner) = &self.inner {
            if !inner.from.is_empty() {
                let ident_str = inner.ident.to_string();
                let ident = &inner.ident;
                return quote!(.field(#ident_str, &self.#ident()));
            }
        }
        quote!()
    }

    fn default(&self) -> TokenStream {
        let default = &self.default;

        if let Some(inner) = &self.inner {
            if !inner.into.is_empty() {
                let ident = &inner.ident;
                let with_ident = format_ident!("with_{ident}");
                return quote!(this = this.#with_ident(#default););
            }
        }
        let offset = self.offset;
        let base_ty = &self.base_ty;
        quote!(this.0 |= (#default as #base_ty) << #offset;)
    }
}

impl ToTokens for Member {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            offset,
            bits,
            base_ty,
            default: _,
            inner:
                Some(MemberInner {
                    ident,
                    ty,
                    attrs,
                    vis,
                    into,
                    from,
                }),
        } = self
        else {
            return Default::default();
        };

        let ident_str = ident.to_string();

        let with_ident = format_ident!("with_{ident}");
        let set_ident = format_ident!("set_{ident}");
        let bits_ident = format_ident!("{}_BITS", ident_str.to_uppercase());
        let offset_ident = format_ident!("{}_OFFSET", ident_str.to_uppercase());

        let location = format!("\n\nBits: {offset}..{}", offset + bits);

        let doc: TokenStream = attrs
            .iter()
            .filter(|a| !a.path().is_ident("bits"))
            .map(ToTokens::to_token_stream)
            .collect();

        let mask = u128::MAX >> (u128::BITS - *bits as u32);
        let mask = syn::LitInt::new(&format!("0x{mask:x}"), Span::mixed_site());

        let mut code = quote! {
            const #bits_ident: usize = #bits;
            const #offset_ident: usize = #offset;
        };

        if !from.is_empty() {
            code.extend(quote! {
                #doc
                #[doc = #location]
                #vis const fn #ident(&self) -> #ty {
                    let this = (self.0 >> #offset) & #mask;
                    #from
                }
            });
        }

        if !into.is_empty() {
            code.extend(quote! {
                #doc
                #[doc = #location]
                #[cfg_attr(debug_assertions, track_caller)]
                #vis const fn #with_ident(self, value: #ty) -> Self {
                    let value: #base_ty = {
                        let this = value;
                        #into
                    };
                    #[allow(unused_comparisons)]
                    debug_assert!(value <= #mask, "value out of bounds");
                    Self(self.0 & !(#mask << #offset) | (value & #mask) << #offset)
                }

                #doc
                #[doc = #location]
                #[cfg_attr(debug_assertions, track_caller)]
                #vis fn #set_ident(&mut self, value: #ty) {
                    *self = self.#with_ident(value);
                }
            });
        }

        tokens.extend(code);
    }
}

/// Distinguish between different types for code generation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum TypeClass {
    /// Booleans with 1 bit size
    Bool,
    /// Unsigned ints with fixes sizes: u8, u64, ...
    UInt,
    /// Signed ints with fixes sizes: i8, i64, ...
    SInt,
    /// Custom types
    Other,
}

/// Field information, including the `bits` attribute
struct Field {
    bits: usize,
    ty: syn::Type,

    default: TokenStream,
    into: TokenStream,
    from: TokenStream,

    access: Access,
}

/// Parses the `bits` attribute that allows specifying a custom number of bits.
fn parse_field(
    base_ty: &syn::Type,
    attrs: &[syn::Attribute],
    ty: &syn::Type,
    ignore: bool,
) -> syn::Result<Field> {
    fn malformed(mut e: syn::Error, attr: &syn::Attribute) -> syn::Error {
        e.combine(syn::Error::new(attr.span(), "malformed #[bits] attribute"));
        e
    }

    let access = if ignore {
        Access::None
    } else {
        Access::ReadWrite
    };

    // Defaults for the different types
    let (class, ty_bits) = type_bits(ty);
    let mut ret = match class {
        TypeClass::Bool => Field {
            bits: ty_bits,
            ty: ty.clone(),
            default: quote!(false),
            into: quote!(this as _),
            from: quote!(this != 0),
            access,
        },
        TypeClass::SInt => Field {
            bits: ty_bits,
            ty: ty.clone(),
            default: quote!(0),
            into: quote!(),
            from: quote!(),
            access,
        },
        TypeClass::UInt => Field {
            bits: ty_bits,
            ty: ty.clone(),
            default: quote!(0),
            into: quote!(this as _),
            from: quote!(this as _),
            access,
        },
        TypeClass::Other => Field {
            bits: ty_bits,
            ty: ty.clone(),
            default: quote!(),
            into: quote!(#ty::into_bits(this)),
            from: quote!(#ty::from_bits(this)),
            access,
        },
    };

    // Find and parse the bits attribute
    for attr in attrs {
        let syn::Attribute {
            style: syn::AttrStyle::Outer,
            meta: syn::Meta::List(syn::MetaList { path, tokens, .. }),
            ..
        } = attr
        else {
            continue;
        };
        if path.is_ident("bits") {
            let span = tokens.span();
            let BitsAttr {
                bits,
                default,
                into,
                from,
                access,
            } = syn::parse2(tokens.clone()).map_err(|e| malformed(e, attr))?;

            // bit size
            if let Some(bits) = bits {
                if bits == 0 {
                    return Err(syn::Error::new(span, "bits cannot bit 0"));
                }
                if ty_bits != 0 && bits > ty_bits {
                    return Err(syn::Error::new(span, "overflowing field type"));
                }
                ret.bits = bits;
            }

            // read/write access
            if let Some(access) = access {
                if ignore {
                    return Err(syn::Error::new(
                        tokens.span(),
                        "'access' is not supported for padding",
                    ));
                }
                ret.access = access;
            }

            // conversion
            if let Some(into) = into {
                if ret.access == Access::None {
                    return Err(syn::Error::new(
                        into.span(),
                        "'into' and 'from' are not supported on padding",
                    ));
                }
                ret.into = quote!(#into(this));
            }
            if let Some(from) = from {
                if ret.access == Access::None {
                    return Err(syn::Error::new(
                        from.span(),
                        "'into' and 'from' are not supported on padding",
                    ));
                }
                ret.from = quote!(#from(this));
            }
            if let Some(default) = default {
                ret.default = default.into_token_stream();
            }
        }
    }

    if ret.bits == 0 {
        return Err(syn::Error::new(
            ty.span(),
            "Custom types and isize/usize require an explicit bit size",
        ));
    }

    // Signed integers need some special handling...
    if !ignore && ret.access != Access::None && class == TypeClass::SInt {
        let bits = ret.bits as u32;
        let mask = u128::MAX >> (u128::BITS - ret.bits as u32);
        let mask = syn::LitInt::new(&format!("0x{mask:x}"), Span::mixed_site());
        if ret.into.is_empty() {
            // Bounds check and remove leading ones from negative values
            ret.into = quote! {{
                debug_assert!({
                    let m = #ty::MIN >> (#ty::BITS - #bits);
                    m <= this && this <= -(m + 1)
                });
                (this as #base_ty & #mask)
            }};
        }
        if ret.from.is_empty() {
            // Sign extend negative values
            ret.from = quote! {{
                let shift = #ty::BITS - #bits;
                ((this as #ty) << shift) >> shift
            }};
        }
    }

    Ok(ret)
}

/// The bits attribute of the fields of a bitfield struct
struct BitsAttr {
    bits: Option<usize>,
    default: Option<syn::Expr>,
    into: Option<syn::Path>,
    from: Option<syn::Path>,
    access: Option<Access>,
}

impl Parse for BitsAttr {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut attr = Self {
            bits: None,
            default: None,
            into: None,
            from: None,
            access: None,
        };
        if let Ok(bits) = syn::LitInt::parse(input) {
            attr.bits = Some(bits.base10_parse()?);
            if !input.is_empty() {
                <Token![,]>::parse(input)?;
            }
        }
        // parse remainder
        if !input.is_empty() {
            loop {
                let ident = syn::Ident::parse(input)?;

                <Token![=]>::parse(input)?;

                if ident == "default" {
                    attr.default = Some(input.parse()?);
                } else if ident == "into" {
                    attr.into = Some(input.parse()?);
                } else if ident == "from" {
                    attr.from = Some(input.parse()?);
                } else if ident == "access" {
                    attr.access = Some(input.parse()?);
                }

                if input.is_empty() {
                    break;
                }

                <Token![,]>::parse(input)?;
            }
        }
        Ok(attr)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    ReadWrite,
    ReadOnly,
    WriteOnly,
    None,
}

impl Parse for Access {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mode = input.parse::<Ident>()?;

        if mode == "RW" {
            Ok(Access::ReadWrite)
        } else if mode == "RO" {
            Ok(Access::ReadOnly)
        } else if mode == "WO" {
            Ok(Access::WriteOnly)
        } else if mode == "None" {
            Ok(Access::None)
        } else {
            Err(syn::Error::new(
                mode.span(),
                "Invalid access mode, only RW, RO, WO, or None are allowed",
            ))
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Order {
    Lsb,
    Msb,
}

/// The bitfield macro parameters
struct Params {
    ty: syn::Type,
    bits: usize,
    debug: bool,
    default: bool,
    order: Order,
}

impl Parse for Params {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let Ok(ty) = syn::Type::parse(input) else {
            return Err(syn::Error::new(input.span(), "unknown type"));
        };
        let (class, bits) = type_bits(&ty);
        if class != TypeClass::UInt {
            return Err(syn::Error::new(input.span(), "unsupported type"));
        }

        let mut debug = true;
        let mut default = true;
        let mut order = Order::Lsb;

        // try parse additional args
        while <Token![,]>::parse(input).is_ok() {
            let ident = Ident::parse(input)?;
            <Token![=]>::parse(input)?;
            match ident.to_string().as_str() {
                "debug" => {
                    let value = syn::LitBool::parse(input)?.value;
                    debug = value;
                }
                "default" => {
                    let value = syn::LitBool::parse(input)?.value;
                    default = value;
                }
                "order" => {
                    let value = match syn::Ident::parse(input)?.to_string().as_str() {
                        "Msb" | "msb" => Order::Msb,
                        "Lsb" | "lsb" => Order::Lsb,
                        _ => return Err(syn::Error::new(ident.span(), "unknown value for order")),
                    };
                    order = value;
                }
                _ => return Err(syn::Error::new(ident.span(), "unknown argument")),
            };
        }

        Ok(Params {
            ty,
            bits,
            debug,
            default,
            order,
        })
    }
}

/// Returns the number of bits for a given type
fn type_bits(ty: &syn::Type) -> (TypeClass, usize) {
    let syn::Type::Path(syn::TypePath { path, .. }) = ty else {
        return (TypeClass::Other, 0);
    };
    let Some(ident) = path.get_ident() else {
        return (TypeClass::Other, 0);
    };
    if ident == "bool" {
        return (TypeClass::Bool, 1);
    }
    if ident == "isize" || ident == "usize" {
        return (TypeClass::UInt, 0); // they have architecture dependend sizes
    }
    macro_rules! integer {
        ($ident:ident => $($uint:ident),* ; $($sint:ident),*) => {
            match ident {
                $(_ if ident == stringify!($uint) => (TypeClass::UInt, $uint::BITS as _),)*
                $(_ if ident == stringify!($sint) => (TypeClass::SInt, $sint::BITS as _),)*
                _ => (TypeClass::Other, 0)
            }
        };
    }
    integer!(ident => u8, u16, u32, u64, u128 ; i8, i16, i32, i64, i128)
}

#[cfg(test)]
mod test {
    use quote::quote;

    use crate::{Access, BitsAttr, Order, Params};

    #[test]
    fn parse_args() {
        let args = quote!(u64);
        let params = syn::parse2::<Params>(args).unwrap();
        assert!(params.bits == u64::BITS as usize && params.debug == true);

        let args = quote!(u32, debug = false);
        let params = syn::parse2::<Params>(args).unwrap();
        assert!(params.bits == u32::BITS as usize && params.debug == false);

        let args = quote!(u32, order = Msb);
        let params = syn::parse2::<Params>(args).unwrap();
        assert!(params.bits == u32::BITS as usize && params.order == Order::Msb);
    }

    #[test]
    fn parse_bits() {
        let args = quote!(8);
        let attr = syn::parse2::<BitsAttr>(args).unwrap();
        assert_eq!(attr.bits, Some(8));
        assert!(attr.default.is_none());
        assert!(attr.into.is_none());
        assert!(attr.from.is_none());
        assert!(attr.access.is_none());

        let args = quote!(8, default = 8, access = RW);
        let attr = syn::parse2::<BitsAttr>(args).unwrap();
        assert_eq!(attr.bits, Some(8));
        assert!(attr.default.is_some());
        assert!(attr.into.is_none());
        assert!(attr.from.is_none());
        assert_eq!(attr.access, Some(Access::ReadWrite));

        let args = quote!(access = RO);
        let attr = syn::parse2::<BitsAttr>(args).unwrap();
        assert_eq!(attr.bits, None);
        assert!(attr.default.is_none());
        assert!(attr.into.is_none());
        assert!(attr.from.is_none());
        assert_eq!(attr.access, Some(Access::ReadOnly));

        let args = quote!(default = 8, access = WO);
        let attr = syn::parse2::<BitsAttr>(args).unwrap();
        assert_eq!(attr.bits, None);
        assert!(attr.default.is_some());
        assert!(attr.into.is_none());
        assert!(attr.from.is_none());
        assert_eq!(attr.access, Some(Access::WriteOnly));

        let args = quote!(
            3,
            into = into_something,
            default = 1,
            from = from_something,
            access = None
        );
        let attr = syn::parse2::<BitsAttr>(args).unwrap();
        assert_eq!(attr.bits, Some(3));
        assert!(attr.default.is_some());
        assert!(attr.into.is_some());
        assert!(attr.from.is_some());
        assert_eq!(attr.access, Some(Access::None));
    }

    #[test]
    fn parse_access_mode() {
        let args = quote!(RW);
        let mode = syn::parse2::<Access>(args).unwrap();
        assert_eq!(mode, Access::ReadWrite);

        let args = quote!(RO);
        let mode = syn::parse2::<Access>(args).unwrap();
        assert_eq!(mode, Access::ReadOnly);

        let args = quote!(WO);
        let mode = syn::parse2::<Access>(args).unwrap();
        assert_eq!(mode, Access::WriteOnly);

        let args = quote!(None);
        let mode = syn::parse2::<Access>(args).unwrap();
        assert_eq!(mode, Access::None);

        let args = quote!(garbage);
        let mode = syn::parse2::<Access>(args);
        assert!(mode.is_err());
    }
}
