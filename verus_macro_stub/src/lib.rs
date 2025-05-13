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
