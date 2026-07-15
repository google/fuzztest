use convert_case::Case;
use convert_case::Casing;
use proc_macro2::Span;
use proc_macro2::TokenStream;
use quote::quote;
use syn::parse_quote;
use syn::Expr;
use syn::Generics;
use syn::Ident;
use syn::Lifetime;
use syn::Signature;

use super::fn_item_utils::extract_test_function_arguments;
use super::fn_item_utils::fn_sig_to_bare_type;
use super::fuzztest_domain::generate_fuzztest_domain;
use super::import_fuzztest_crate;
use super::TestFnArgument;

const USER_VALUE_LIFETIME_GENERIC_NAME: &str = "'user";

#[derive(Clone, Debug)]
pub struct FuzzTestObjectDefinitionAndFactory {
    pub fuzztest_object_factory_name: Ident,
    pub fuzztest_object_tokenstream: TokenStream,
}

#[derive(Clone, Debug)]
pub struct GTestDefinition {
    pub gtest_tokens: TokenStream,
}

/// A context struct holding the pre-computed information and token streams required
/// to generate the fuzz test registration, struct definitions, and integration with the test framework.
///
/// This context is created once per property function.
pub struct FuzzTestRegistrationCtx<'a> {
    test_fn_signature: &'a Signature,
    test_fn_ident: &'a Ident,
    prop_fn_ident: Ident,
    test_fn_args: Vec<TestFnArgument<'a>>,
    crate_name: TokenStream,
    fuzz_test_domain_definition: TokenStream,
    fuzz_test_domain_field_names: Vec<Ident>,
    fuzztest_struct_instance_tokens: TokenStream,
    fuzz_test_struct_factory_fn_name: Ident,
}

impl<'a> FuzzTestRegistrationCtx<'a> {
    /// Creates a new registration context from a property function signature and its domain constructors.
    ///
    /// This method analyzes the inputs, derives necessary identifiers and lifetime generics, and
    /// pre-computes the tokenstream for the fuzz test struct instance.
    pub fn new(
        test_fn_signature: &'a Signature,
        domain_ctors: impl IntoIterator<Item = &'a Expr>,
    ) -> syn::Result<Self> {
        let user_value_lifetime_generic =
            Lifetime::new(USER_VALUE_LIFETIME_GENERIC_NAME, Span::call_site());

        let test_fn_args =
            extract_test_function_arguments(test_fn_signature, &user_value_lifetime_generic)?;
        if test_fn_args.is_empty() {
            return Err(syn::Error::new_spanned(
                test_fn_signature,
                "fuzztest requires at least one argument for the property function",
            ));
        }

        let test_fn_generics = &test_fn_signature.generics;
        if test_fn_generics.type_params().count() > 0 || test_fn_generics.const_params().count() > 0
        {
            return Err(syn::Error::new_spanned(
                test_fn_generics,
                "Property function should not have any Type or Const generics",
            ));
        }

        let test_fn_ident = &test_fn_signature.ident;
        let prop_fn_ident = quote::format_ident!("__property_fn__{}", test_fn_ident);
        let domain_ctors = domain_ctors.into_iter().collect::<Vec<_>>();
        let fuzz_test_struct_name =
            quote::format_ident!("__FuzzTest{}", test_fn_ident.to_string().to_case(Case::Pascal));
        let crate_name = import_fuzztest_crate();

        let domain_struct_name = quote::format_ident!(
            "__FuzzTest{}StateWrapper",
            test_fn_ident.to_string().to_case(Case::Pascal)
        );

        let (fuzz_test_domain_definition, fuzz_test_domain_field_names) = generate_fuzztest_domain(
            &domain_struct_name,
            &test_fn_args,
            &user_value_lifetime_generic,
        );

        let fuzztest_struct_instance_tokens = quote!(
          #fuzz_test_struct_name {
              domain: #domain_struct_name {
                  #(#fuzz_test_domain_field_names: #domain_ctors),*
              },
              test_fn: #prop_fn_ident
          }
        );

        let fuzz_test_struct_factory_fn_name =
            quote::format_ident!("{}_factory", fuzz_test_struct_name);

        Ok(Self {
            test_fn_signature,
            test_fn_ident,
            prop_fn_ident,
            test_fn_args,
            crate_name,
            fuzz_test_domain_definition,
            fuzz_test_domain_field_names,
            fuzztest_struct_instance_tokens,
            fuzz_test_struct_factory_fn_name,
        })
    }

    pub fn prop_fn_ident(&self) -> &Ident {
        &self.prop_fn_ident
    }

    /// Generates a GoogleTest-compatible test function that wraps the fuzz test.
    ///
    /// This allows the fuzz test to be executed as a regular tests.
    pub fn generate_gtest(&self) -> syn::Result<GTestDefinition> {
        let gtest_name = &self.test_fn_ident;
        let crate_name = &self.crate_name;
        let test_fn_name = self.test_fn_ident.to_string();
        let fuzz_test_factory = &self.fuzz_test_struct_factory_fn_name;

        let tokens = quote!(
            #[::googletest::prelude::gtest]
            fn #gtest_name() {
                // Note: In this setup, `module_path!()` returns a path that starts with the crate name
                // (e.g., `crate_name::module::path`). We want to strip this prefix to make the
                // test name similar to standard `libtest` paths.
                let full_test_name = concat!(module_path!(), "::", #test_fn_name);
                let test_name = full_test_name
                    .split_once("::")
                    .expect("Crate name is always the first path segment")
                    .1;
                let manager = #crate_name::worker::RustFuzzTestAdapterManager {
                    test_name,
                    fuzz_test_factory: #fuzz_test_factory,
                };
                #crate_name::worker::process(manager);
            }
        );

        Ok(GTestDefinition { gtest_tokens: tokens })
    }

    /// Generates the test `struct` that will contain the state of the test:
    ///  - the domain of the property function inputs
    ///  - the property function itself
    ///
    /// The generated test `struct` object will implement the FuzzTest trait.
    pub fn generate_test_registration(&self) -> syn::Result<FuzzTestObjectDefinitionAndFactory> {
        let crate_name = &self.crate_name;
        let user_value_lifetime_generic =
            Lifetime::new(USER_VALUE_LIFETIME_GENERIC_NAME, Span::call_site());
        let test_fn_args = &self.test_fn_args;
        let test_fn_args_len = test_fn_args.len();

        let test_fn_type = fn_sig_to_bare_type(self.test_fn_signature)?;

        let test_fn_ident = self.test_fn_ident;
        let fuzz_test_struct_name =
            quote::format_ident!("__FuzzTest{}", test_fn_ident.to_string().to_case(Case::Pascal));
        let domain_struct_name = quote::format_ident!(
            "__FuzzTest{}StateWrapper",
            test_fn_ident.to_string().to_case(Case::Pascal)
        );
        let test_fn_name = test_fn_ident.to_string();
        let fuzz_test_struct_factory_fn_name = &self.fuzz_test_struct_factory_fn_name;

        let domain_generics =
            (0..test_fn_args_len).map(|idx| quote::format_ident!("T{idx}")).collect::<Vec<_>>();
        let corpus_generics = domain_generics
            .iter()
            .map(|generic| parse_quote!(#generic::CorpusValue))
            .collect::<Vec<syn::Type>>();

        let mut generics: Generics = parse_quote! { < #(#domain_generics),* > };

        let test_fn_args_with_generics = test_fn_args
            .iter()
            .zip(generics.type_params().cloned())
            .zip(corpus_generics.iter())
            .collect::<Vec<_>>();

        let where_clauses = generics.make_where_clause();
        for ((TestFnArgument { ty, .. }, syn::TypeParam { ident: domain_gen, .. }), corpus_gen) in
            &test_fn_args_with_generics
        {
            where_clauses.predicates.push(
          parse_quote! {
            for <#user_value_lifetime_generic> #domain_gen: #crate_name::domains::Domain<UserValue<#user_value_lifetime_generic> = #ty >
        });
            where_clauses.predicates.push(parse_quote! { #corpus_gen: 'static });
        }

        let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

        let fuzztest_instance = &self.fuzztest_struct_instance_tokens;
        let fuzz_test_domain_field_names = &self.fuzz_test_domain_field_names;
        let fuzz_test_domain_definition = &self.fuzz_test_domain_definition;

        let fuzztest_struct_definition_and_factory = quote! {
          #fuzz_test_domain_definition

          struct #fuzz_test_struct_name #generics {
            domain: #domain_struct_name #generics,
            test_fn: #test_fn_type
          }

          impl #impl_generics #crate_name::internal::FuzzTest for #fuzz_test_struct_name #ty_generics #where_clause {
              fn name(&self) -> &'static str {
                  #test_fn_name
              }
              fn activate(&mut self) {
                  todo!("Not implemented!")
              }
              fn mutate(&mut self) {
                  todo!("Not implemented!")
              }
              fn execute<'a>(&self, args: &'a #crate_name::domains::GenericCorpusValue) -> bool {
                  use #crate_name::domains::Domain;

                  let wrapper = args
                                .downcast_ref::<#domain_struct_name<#(#corpus_generics),*>>()
                                .expect("Attempt to recover user value before testing failed.");

                  let user_value = self.domain.get_user_value(wrapper).expect("Failed to get user value from corpus value");

                  let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.test_fn)(#(user_value.#fuzz_test_domain_field_names),* ) ));

                  result.is_ok()
              }
              fn print_finding_report(&self) {
                  todo!("Not implemented!")
              }
              fn domains(&self) -> &dyn #crate_name::domains::GenericDomain {
                &self.domain
              }
          }

          fn #fuzz_test_struct_factory_fn_name() -> #crate_name::internal::BoxedFuzzTest {
            ::std::boxed::Box::new(#fuzztest_instance)
          }
        };

        Ok(FuzzTestObjectDefinitionAndFactory {
            fuzztest_object_factory_name: fuzz_test_struct_factory_fn_name.clone(),
            fuzztest_object_tokenstream: fuzztest_struct_definition_and_factory,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::matchers;
    use googletest::prelude::*;

    #[googletest::test]
    fn test_generate_test_registration() {
        let sig: Signature = parse_quote! { fn test_fuzz(a: i32, b: std::string::String) };
        let expr1: Expr =
            parse_quote! { ::fuzztest::domains::arbitrary::Arbitrary::<i32>::default() };
        let expr2: Expr =
            parse_quote! { ::fuzztest::domains::arbitrary::Arbitrary::<String>::default() };
        let context = FuzzTestRegistrationCtx::new(&sig, [&expr1, &expr2]).unwrap();
        let FuzzTestObjectDefinitionAndFactory {
            fuzztest_object_factory_name,
            fuzztest_object_tokenstream,
        } = context.generate_test_registration().unwrap();
        expect_that!(
            fuzztest_object_factory_name,
            eq(&quote::format_ident!("__FuzzTestTestFuzz_factory"))
        );
        expect_that!(
          fuzztest_object_tokenstream.to_string(), ends_with( quote! {
              struct __FuzzTestTestFuzz<T0, T1> {
                domain: __FuzzTestTestFuzzStateWrapper<T0, T1>,
                test_fn: fn(i32, std::string::String)
              }

              impl<T0, T1> ::fuzztest::internal::FuzzTest for __FuzzTestTestFuzz<T0, T1>
              where for <'user> T0: ::fuzztest::domains::Domain<UserValue<'user> = i32>,
                    T0::CorpusValue: 'static,
                    for <'user> T1: ::fuzztest::domains::Domain<UserValue<'user> = std::string::String>,
                    T1::CorpusValue: 'static {
                  fn name(&self) -> &'static str {
                    "test_fuzz"
                  }
                  fn activate(&mut self) {
                    todo!("Not implemented!")
                  }
                  fn mutate(&mut self) {
                    todo!("Not implemented!")
                  }
                  fn execute<'a>(&self, args: &'a ::fuzztest::domains::GenericCorpusValue) -> bool {
                    use ::fuzztest::domains::Domain;

                    let wrapper = args
                            .downcast_ref::<__FuzzTestTestFuzzStateWrapper<T0::CorpusValue, T1::CorpusValue>>()
                            .expect("Attempt to recover user value before testing failed.");

                    let user_value = self.domain.get_user_value(wrapper).expect("Failed to get user value from corpus value");
                    // Safety: Data is not reused after the test.
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.test_fn)(user_value.a, user_value.b) ));

                    result.is_ok()
                  }
                  fn print_finding_report(&self) {
                    todo!("Not implemented!")
                  }
                  fn domains(&self) -> &dyn ::fuzztest::domains::GenericDomain {
                    &self.domain
                  }
              }

              fn __FuzzTestTestFuzz_factory() -> ::fuzztest::internal::BoxedFuzzTest {
                ::std::boxed::Box::new(__FuzzTestTestFuzz {
                  domain: __FuzzTestTestFuzzStateWrapper {
                    a: ::fuzztest::domains::arbitrary::Arbitrary::<i32>::default(),
                    b: ::fuzztest::domains::arbitrary::Arbitrary::<String>::default()
                  },
                  test_fn: __property_fn__test_fuzz
                })
              }
            }
            .to_string())
        );
    }

    #[googletest::test]
    fn test_generate_gtest() {
        let sig: Signature = parse_quote! { fn test_fuzz(a: i32, b: std::string::String) };
        let expr1: Expr =
            parse_quote! { ::fuzztest::domains::arbitrary::Arbitrary::<i32>::default() };
        let expr2: Expr =
            parse_quote! { ::fuzztest::domains::arbitrary::Arbitrary::<String>::default() };
        let context = FuzzTestRegistrationCtx::new(&sig, [&expr1, &expr2]).unwrap();
        let GTestDefinition { gtest_tokens } = context.generate_gtest().unwrap();

        // test that the gtest was generated
        expect_that!(
            gtest_tokens.to_string(),
            matchers::contains_substring(
                quote! {
                    #[::googletest::prelude::gtest]
                    fn test_fuzz()
                }
                .to_string()
            )
        );

        // test that the test_name is the test path
        expect_that!(
            gtest_tokens.to_string(),
            matchers::contains_substring(
                quote! {
                    let full_test_name = concat!(module_path!(), "::", "test_fuzz");
                    let test_name = full_test_name
                        .split_once("::")
                        .expect("Crate name is always the first path segment")
                        .1;
                }
                .to_string()
            )
        )
    }
}
