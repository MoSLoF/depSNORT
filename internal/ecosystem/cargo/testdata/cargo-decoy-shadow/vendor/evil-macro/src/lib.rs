use proc_macro::TokenStream;

#[proc_macro_derive(Benign)]
pub fn derive_benign(input: TokenStream) -> TokenStream {
    input
}
