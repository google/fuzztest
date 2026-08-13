// Copyright 2026 Google LLC
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
