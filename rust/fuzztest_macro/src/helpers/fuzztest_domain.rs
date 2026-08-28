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

use proc_macro2::TokenStream;
use quote::quote;
use syn::parse_quote;
use syn::Generics;
use syn::Ident;

use super::import_fuzztest_crate;
use super::TestFnArgument;

/// Generates a wrapper domain that will contain all domains of the test
/// function arguments.
pub fn generate_fuzztest_domain<'a, 'b: 'a>(
    domain_struct_name: &Ident,
    test_fn_args: impl IntoIterator<Item = &'a TestFnArgument<'b>>,
    user_value_lifetime_generic: &syn::Lifetime,
) -> (TokenStream, Vec<Ident>) {
    let crate_name = import_fuzztest_crate();
    let test_fn_args = test_fn_args.into_iter().collect::<Vec<_>>();

    let domain_generics =
        (0..test_fn_args.len()).map(|idx| quote::format_ident!("T{idx}")).collect::<Vec<_>>();

    let corpus_domain_generics = domain_generics
        .iter()
        .map(|generic| parse_quote!(#generic::CorpusValue))
        .collect::<Vec<syn::Type>>();
    let user_value_domain_generics = domain_generics
        .iter()
        .map(|generic| parse_quote!(#generic::UserValue<#user_value_lifetime_generic>))
        .collect::<Vec<syn::Type>>();
    let mut generics: Generics = parse_quote! { < #(#domain_generics),* > };

    let test_fn_args_with_generics =
        test_fn_args.into_iter().zip(generics.type_params().cloned()).collect::<Vec<_>>();

    let mut field_names = vec![];
    let mut domain_field_types = vec![];

    let where_clauses = generics.make_where_clause();
    for (TestFnArgument { ty, name }, syn::TypeParam { ident: domain_gen, .. }) in
        &test_fn_args_with_generics
    {
        where_clauses.predicates.push(
          parse_quote! {
            for <#user_value_lifetime_generic> #domain_gen: #crate_name::domains::Domain<UserValue<#user_value_lifetime_generic> = #ty >
          });
        where_clauses.predicates.push(parse_quote! { #domain_gen::CorpusValue: #crate_name::serde::Serialize + #crate_name::serde::de::DeserializeOwned + ::std::clone::Clone });
        field_names.push((*name).clone());
        domain_field_types.push(domain_gen);
    }

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let serde_crate_path = format!("{}", quote!(#crate_name::serde));

    let domain_definition_tokens = quote! {
      #[derive(#crate_name::serde::Serialize, #crate_name::serde::Deserialize, ::std::fmt::Debug, ::std::clone::Clone)]
      #[serde(crate = #serde_crate_path)]
      struct #domain_struct_name #ty_generics {
        #(#field_names : #domain_field_types),*
      }

      impl #impl_generics #crate_name::domains::Domain for #domain_struct_name #ty_generics #where_clause {
        type UserValue<#user_value_lifetime_generic> = #domain_struct_name <#(#user_value_domain_generics),*>;
        type CorpusValue = #domain_struct_name <#(#corpus_domain_generics),*>;

        fn init(&mut self, rng: &mut dyn ::fuzztest::reexports::rand::Rng) -> ::fuzztest::reexports::anyhow::Result<Self::CorpusValue> {
          Ok(#domain_struct_name {
            #(#field_names: self.#field_names.init(rng)?),*
          })
        }

        fn mutate(
            &mut self,
            val: &mut Self::CorpusValue,
            rng: &mut dyn ::fuzztest::reexports::rand::Rng,
            only_shrink: bool,
        ) -> ::fuzztest::reexports::anyhow::Result<()> {
          #( self.#field_names.mutate(&mut val.#field_names, rng, only_shrink)?; )*
          Ok(())
        }

        fn get_user_value<'a>(&self, corpus_value: &'a Self::CorpusValue) -> ::fuzztest::reexports::anyhow::Result<Self::UserValue<'a>> {
          Ok(#domain_struct_name {
            #(#field_names: self.#field_names.get_user_value(&corpus_value.#field_names)?),*
          })
        }

        fn from_value(&self, value: Self::UserValue<'_>) -> ::fuzztest::reexports::anyhow::Result<Self::CorpusValue> {
          Ok(#domain_struct_name {
            #(#field_names: self.#field_names.from_value(value.#field_names)?),*
          })
        }

        fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> ::fuzztest::reexports::anyhow::Result<()> {
          #( self.#field_names.validate_corpus_value(&corpus_value.#field_names)?; )*
          Ok(())
        }
      }
    };
    (domain_definition_tokens, field_names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;

    #[googletest::test]
    fn test_generate_fuzztest_domain() {
        let (domain_definition_tokens, field_names) = generate_fuzztest_domain(
            &quote::format_ident!("__FuzzTestTestFuzzStateWrapper"),
            &[
                TestFnArgument {
                    name: &quote::format_ident!("a"),
                    ty: parse_quote!(&'user Vec<&'user i32>),
                },
                TestFnArgument {
                    name: &quote::format_ident!("b"),
                    ty: parse_quote!(std::string::String),
                },
            ],
            &parse_quote!('user),
        );
        expect_that!(
            field_names,
            elements_are![eq(&quote::format_ident!("a")), eq(&quote::format_ident!("b"))]
        );
        expect_that!(domain_definition_tokens.to_string(), eq( &quote! {
            #[derive(::fuzztest::serde::Serialize, ::fuzztest::serde::Deserialize, ::std::fmt::Debug, ::std::clone::Clone)]
            #[serde(crate = ":: fuzztest :: serde")]
            struct __FuzzTestTestFuzzStateWrapper<T0, T1> {
              a: T0,
              b: T1
            }

            impl<T0, T1> ::fuzztest::domains::Domain for __FuzzTestTestFuzzStateWrapper<T0, T1>
            where for < 'user > T0: ::fuzztest::domains::Domain<UserValue< 'user > = &'user Vec<&'user i32> >,
                  T0::CorpusValue: ::fuzztest::serde::Serialize + ::fuzztest::serde::de::DeserializeOwned + ::std::clone::Clone,
                  for < 'user > T1: ::fuzztest::domains::Domain<UserValue< 'user > = std::string::String>,
                  T1::CorpusValue: ::fuzztest::serde::Serialize + ::fuzztest::serde::de::DeserializeOwned + ::std::clone::Clone {
              type UserValue<'user> = __FuzzTestTestFuzzStateWrapper<T0::UserValue<'user>, T1::UserValue<'user> >;
              type CorpusValue = __FuzzTestTestFuzzStateWrapper<T0::CorpusValue, T1::CorpusValue>;

              fn init(&mut self, rng: &mut dyn ::fuzztest::reexports::rand::Rng) -> ::fuzztest::reexports::anyhow::Result<Self::CorpusValue> {
                Ok(__FuzzTestTestFuzzStateWrapper {
                  a: self.a.init(rng)?,
                  b: self.b.init(rng)?
                })
              }

              fn mutate(
                  &mut self,
                  val: &mut Self::CorpusValue,
                  rng: &mut dyn ::fuzztest::reexports::rand::Rng,
                  only_shrink: bool,
              ) -> ::fuzztest::reexports::anyhow::Result<()> {
                self.a.mutate(&mut val.a, rng, only_shrink)?;
                self.b.mutate(&mut val.b, rng, only_shrink)?;
                Ok(())
              }

              fn get_user_value<'a>(&self, corpus_value: &'a Self::CorpusValue) -> ::fuzztest::reexports::anyhow::Result<Self::UserValue<'a>> {
                Ok(__FuzzTestTestFuzzStateWrapper {
                  a: self.a.get_user_value(&corpus_value.a)?,
                  b: self.b.get_user_value(&corpus_value.b)?
                })
              }

              fn from_value(&self, value: Self::UserValue<'_>) -> ::fuzztest::reexports::anyhow::Result<Self::CorpusValue> {
                Ok(__FuzzTestTestFuzzStateWrapper {
                  a: self.a.from_value(value.a)?,
                  b: self.b.from_value(value.b)?
                })
              }

              fn validate_corpus_value(&self, corpus_value: &Self::CorpusValue) -> ::fuzztest::reexports::anyhow::Result<()> {
                self.a.validate_corpus_value(&corpus_value.a)?;
                self.b.validate_corpus_value(&corpus_value.b)?;
                Ok(())
              }
            }
          }
          .to_string())
      );
    }
}
