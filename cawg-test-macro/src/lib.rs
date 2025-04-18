use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn cawg_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let name = &input.sig.ident;
    let block = &input.block;
    let attrs = &input.attrs;
    let vis = &input.vis;

    let expanded = quote! {
        #(#attrs)*
        #[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
        #[cfg_attr(
            all(target_arch = "wasm32", not(target_os = "wasi")),
            wasm_bindgen_test::wasm_bindgen_test
        )]
        #[cfg_attr(target_os = "wasi", wstd::test)]
        #vis async fn #name() #block
    };

    TokenStream::from(expanded)
}
