use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn fuzztest(_args: TokenStream, _input: TokenStream) -> TokenStream {
    todo!("Not implemented yet.")
}
