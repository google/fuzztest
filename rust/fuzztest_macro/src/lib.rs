/// Modules here cannot be public (ie: `pub`) because a proc-macro crate cannot export anything else
/// other than a proc-macro. That is to say, a function tagged with `#[proc_macro]`,
/// `#[proc_macro_attribute]`, `#[proc_macro_derive]`
mod helpers;

use proc_macro::TokenStream;

use quote::quote;
use syn::parse::{Parse, ParseStream, Parser};
use syn::{parse_macro_input, Item};

use helpers::test_registration::FuzzTestObjectDefinitionAndFactory;
use helpers::test_registration::FuzzTestRegistrationCtx;
use helpers::test_registration::GTestDefinition;

#[derive(Debug)]
struct FuzzTestArg {
    _ident: syn::Ident,
    _eq_token: syn::Token![=],
    domain_ty: syn::Expr,
}

impl Parse for FuzzTestArg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self { _ident: input.parse()?, _eq_token: input.parse()?, domain_ty: input.parse()? })
    }
}

/// The `fuzztest` macro is used to generate and register a fuzz test object to be used by a fuzz
/// testing engine.
///
/// The macro takes a list of arguments, where each argument is a domain object used to generate
/// values for the property function inputs.
///
/// Example usage:
/// ```markdown
/// ```
/// # use fuzztest::fuzztest;
/// # use fuzztest::domains::arbitrary::Arbitrary;
/// # use fuzztest::domains::range::InRange;
///
/// #[fuzztest(a = Arbitrary::<i32>::default(), b = InRange::new(0, 10))]
/// fn fuzz_test_function(a: i32, b: i32) {
///     assert_eq!(a, b);
/// }
/// ```
/// ```
///
#[proc_macro_attribute]
pub fn fuzztest(args: TokenStream, input: TokenStream) -> TokenStream {
    let item = parse_macro_input!(input as Item);

    let syn::Item::Fn(mut test_fn) = item else {
        return syn::Error::new_spanned(item, "not a function").into_compile_error().into();
    };

    let original_ident = test_fn.sig.ident.clone();
    let fuzztest_name = original_ident.to_string();

    // TODO(mathuxny-73): Support the case where there are no arguments. Probably we should return an error
    //  in this case as it may not make sense to have a FuzzTest without input.
    let args =
        syn::punctuated::Punctuated::<FuzzTestArg, syn::Token![,]>::parse_terminated.parse(args);

    let args = match args {
        Ok(args) => args,
        Err(e) => return e.into_compile_error().into(),
    };

    let domain_ctors = args.iter().map(|arg| &arg.domain_ty);

    let fuzztest_registration_context =
        match FuzzTestRegistrationCtx::new(&test_fn.sig, domain_ctors) {
            Ok(fuzztest_registration_context) => fuzztest_registration_context,
            Err(e) => return e.into_compile_error().into(),
        };

    let FuzzTestObjectDefinitionAndFactory {
        fuzztest_object_factory_name,
        fuzztest_object_tokenstream,
    } = match fuzztest_registration_context.generate_test_registration() {
        Ok(fuzztest_object) => fuzztest_object,
        Err(e) => return e.into_compile_error().into(),
    };

    let GTestDefinition { gtest_tokens } = match fuzztest_registration_context.generate_gtest() {
        Ok(gtest_tokens) => gtest_tokens,
        Err(e) => return e.into_compile_error().into(),
    };

    test_fn.sig.ident = fuzztest_registration_context.prop_fn_ident().clone();

    let fuzztest_mod_name = quote::format_ident!("__fuzztest_mod__{}", original_ident);

    // TODO(mathuxny-73): Extract the current module path from the invocation of the macro
    //   (ie: from `item.attrs`)
    let tokens = quote! {
        #[allow(non_snake_case)]
        mod #fuzztest_mod_name {
            use super::*;

            #test_fn

            #fuzztest_object_tokenstream

            const _: () = {
                static FUZZTEST_INFO: ::fuzztest::internal::FuzzTestInfo =
                ::fuzztest::internal::FuzzTestInfo {
                    name: #fuzztest_name,
                    file: file!(),
                    line: line!(),
                };

                ::fuzztest::reexports::inventory::submit! {
                ::fuzztest::internal::FuzzTestRegistration {
                    info: &FUZZTEST_INFO,
                    factory: #fuzztest_object_factory_name
                }
                }
            };

            #gtest_tokens
        }
    };
    tokens.into()
}
