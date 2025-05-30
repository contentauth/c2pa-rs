extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn c2pa_test_async(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let attrs = &input.attrs;
    let vis = &input.vis;
    let sig = &input.sig;
    let block = &input.block;

    let result = quote! {
        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(all(target_arch = "wasm32", not(target_os = "wasi")), wasm_bindgen_test)]
        #[cfg_attr(target_os = "wasi", wstd::test)]
        #(#attrs)*
        #vis #sig #block
    };
    result.into()
}
