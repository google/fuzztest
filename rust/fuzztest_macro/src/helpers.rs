use proc_macro2::Span;
use proc_macro2::TokenStream;
use proc_macro_crate::FoundCrate;
use quote::quote;
use syn::Ident;

mod fn_item_utils;
mod fuzztest_domain;
pub mod test_registration;

#[derive(Debug, Clone)]
struct TestFnArgument<'a> {
    name: &'a syn::Ident,
    ty: syn::Type,
}

fn import_fuzztest_crate() -> TokenStream {
    match proc_macro_crate::crate_name("fuzztest") {
        Ok(FoundCrate::Itself) => quote! { crate },
        Ok(FoundCrate::Name(name)) => {
            let ident = Ident::new(&name, Span::call_site());
            quote! { #ident }
        }
        Err(_) => quote! { ::fuzztest },
    }
}
