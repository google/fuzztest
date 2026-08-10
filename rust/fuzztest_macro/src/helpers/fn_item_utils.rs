use syn::parse_quote;
use syn::visit_mut::{self, VisitMut};
use syn::BareFnArg;
use syn::Error;
use syn::FnArg;
use syn::Pat;
use syn::Signature;
use syn::TypeBareFn;

use super::TestFnArgument;

struct LifetimeReplacer<'a> {
    user_value_lifetime_generic: &'a syn::Lifetime,
}

impl<'a> VisitMut for LifetimeReplacer<'a> {
    fn visit_lifetime_mut(&mut self, lifetime: &mut syn::Lifetime) {
        // If the lifetime is `'static`, we don't want to replace it.
        if lifetime.ident != "static" {
            *lifetime = self.user_value_lifetime_generic.clone();
        }
        visit_mut::visit_lifetime_mut(self, lifetime);
    }
}

/// Extracts the type of the arguments of a given function item (ie: a `syn::ItemFn`).
pub fn extract_test_function_arguments<'a>(
    fn_signature: &'a Signature,
    user_value_lifetime_generic: &syn::Lifetime,
) -> syn::Result<Vec<TestFnArgument<'a>>> {
    fn_signature
        .inputs
        .iter()
        .map(|arg| match arg {
            FnArg::Receiver(_) => {
                Err(Error::new_spanned(arg, "Receiver is not supported in property functions."))
            }
            FnArg::Typed(pat_type) => match pat_type.pat.as_ref() {
                Pat::Ident(pat_ident) => {
                    let mut ty = pat_type.ty.as_ref().clone();
                    let mut lifetime_replacer = LifetimeReplacer { user_value_lifetime_generic };
                    lifetime_replacer.visit_type_mut(&mut ty);
                    Ok(TestFnArgument { name: &pat_ident.ident, ty })
                }
                pat => Err(Error::new_spanned(pat, "Expected an identifier")),
            },
        })
        .collect::<syn::Result<Vec<_>>>()
}

/// Extract a bare function pointer type (`syn::TypeBareFn``) from a given
/// signature (`syn::Signature`)
///
/// For example, passing in a `syn::Signature` representing the function
/// `fn test_function(mut a: i32, b: std::string::String)` would yield the
/// following bare function pointer type `fn(i32, std::string::String)`.
///
/// Example usage:
/// ```markdown
/// ```
/// # use syn::parse_quote;
///
/// let signature = parse_quote! {
///   fn test_function(mut a: i32, b: std::string::String)
/// };
///
/// assert_eq!(fn_sig_to_bare_type(&signature), parse_quote!(fn(i32, std::string::String)));
/// ```
/// ```
///
pub fn fn_sig_to_bare_type(fn_sig: &Signature) -> syn::Result<TypeBareFn> {
    let generics = &fn_sig.generics;
    if generics.type_params().count() > 0 || generics.const_params().count() > 0 {
        return Err(Error::new_spanned(
            generics,
            "Property function should not have any Type or Const generics",
        ));
    }

    let bare_input_args = fn_sig
        .inputs
        .iter()
        .map(|arg| match arg {
            FnArg::Receiver(_) => {
                Err(Error::new_spanned(arg, "Receiver is not supported in property functions."))
            }
            FnArg::Typed(pat_type) => Ok(BareFnArg {
                attrs: pat_type.attrs.clone(),
                name: None,
                ty: pat_type.ty.as_ref().clone(),
            }),
        })
        .collect::<syn::Result<Vec<_>>>()?;
    let fn_lifetime_generics = generics.lifetimes().collect::<Vec<_>>();
    let unsafety = &fn_sig.unsafety;
    let abi = &fn_sig.abi;
    let variadic = &fn_sig.variadic;
    let output = &fn_sig.output;
    if fn_lifetime_generics.is_empty() {
        Ok(parse_quote! {
          #unsafety #abi fn (#(#bare_input_args),* #variadic) #output
        })
    } else {
        Ok(parse_quote! {
          for< #(#fn_lifetime_generics),* > #unsafety #abi fn (#(#bare_input_args),* #variadic) #output
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;

    #[googletest::test]
    fn test_extract_test_function_arguments_succeeds() {
        let fn_item: Signature = syn::parse_quote! {
            fn test_function(mut a: i32, b: std::string::String)
        };
        let user_value_lifetime_generic = parse_quote!('user);

        let test_fn_arguments =
            extract_test_function_arguments(&fn_item, &user_value_lifetime_generic);

        expect_that!(
            test_fn_arguments,
            ok(elements_are![
                matches_pattern!(TestFnArgument {
                    name: eq(&&quote::format_ident!("a")),
                    ty: eq(&syn::parse_quote! { i32 }),
                }),
                matches_pattern!(TestFnArgument {
                    name: eq(&&quote::format_ident!("b")),
                    ty: eq(&syn::parse_quote! { std::string::String }),
                })
            ])
        );
    }

    #[googletest::test]
    fn test_extract_test_function_arguments_with_lifetimes_succeeds() {
        let fn_item: Signature = syn::parse_quote! {
            fn test_function<'a, 'b>(mut a: i32, b: &'a str, c: &'b Vec<&'static u8>)
        };
        let user_value_lifetime_generic = parse_quote!('user);

        let test_fn_arguments =
            extract_test_function_arguments(&fn_item, &user_value_lifetime_generic);

        expect_that!(
            test_fn_arguments,
            ok(elements_are![
                matches_pattern!(TestFnArgument {
                    name: eq(&&quote::format_ident!("a")),
                    ty: eq(&syn::parse_quote! { i32 }),
                }),
                matches_pattern!(TestFnArgument {
                    name: eq(&&quote::format_ident!("b")),
                    ty: eq(&syn::parse_quote! { &'user str }),
                }),
                matches_pattern!(TestFnArgument {
                    name: eq(&&quote::format_ident!("c")),
                    ty: eq(&syn::parse_quote! { &'user Vec<&'static u8> }),
                })
            ])
        );
    }

    #[googletest::test]
    fn test_extract_test_function_arguments_fails_with_non_ident_arg() {
        let fn_item: Signature = syn::parse_quote! {
            fn test_function(
              MyStruct { a }: MyStruct, b: std::string::String)
        };
        let user_value_lifetime_generic = parse_quote!('user);

        let test_fn_arguments =
            extract_test_function_arguments(&fn_item, &user_value_lifetime_generic);

        expect_that!(
            test_fn_arguments,
            err(displays_as(contains_substring("Expected an identifier")))
        );
    }

    #[googletest::test]
    fn test_extract_test_function_arguments_fails_with_receiver_arg() {
        let fn_item: Signature = syn::parse_quote! {
            fn test_function(&self, b: std::string::String)
        };
        let user_value_lifetime_generic = parse_quote!('user);

        let test_fn_arguments =
            extract_test_function_arguments(&fn_item, &user_value_lifetime_generic);

        expect_that!(
            test_fn_arguments,
            err(displays_as(contains_substring(
                "Receiver is not supported in property functions."
            )))
        );
    }

    #[googletest::test]
    fn test_convert_fn_sig_to_bare_type_fn_succeeds() {
        expect_that!(
            fn_sig_to_bare_type(&parse_quote! {
              fn test_function(a: i32, b: std::string::String) -> bool
            }),
            ok(eq(&parse_quote! {fn (i32, std::string::String) -> bool }))
        )
    }

    #[googletest::test]
    fn test_convert_fn_sig_with_no_return_type_to_bare_type_fn_succeeds() {
        expect_that!(
            fn_sig_to_bare_type(&parse_quote! {
              fn test_function(a: i32, b: std::string::String)
            }),
            ok(eq(&parse_quote! {fn (i32, std::string::String) }))
        )
    }

    #[googletest::test]
    fn test_convert_fn_sig_with_lifetimes_to_bare_type_fn_succeeds() {
        expect_that!(
            fn_sig_to_bare_type(&parse_quote! {
              fn test_function<'a, 'b>(a: std::vec::Vec<&'a i32>, b: Test<'b>)
            }),
            ok(eq(&parse_quote! {for<'a, 'b> fn (std::vec::Vec<&'a i32>, Test<'b>) }))
        )
    }
}
