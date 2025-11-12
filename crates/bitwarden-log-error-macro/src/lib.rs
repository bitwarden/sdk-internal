//! A procedural macro crate that provides the `log_error` attribute macro for logging errors.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Expr, Ident, ItemFn, Token, parse::Parse, parse::ParseStream, parse_macro_input};

/// Attribute parameters for the log_error macro
struct LogErrorArgs {
    fields: Vec<(Ident, Expr)>,
}

impl Parse for LogErrorArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut fields = Vec::new();

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let value: Expr = input.parse()?;

            fields.push((key, value));

            // Handle trailing comma
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(LogErrorArgs { fields })
    }
}

/// A procedural macro that logs errors returned by the annotated function.
///
/// # Parameters
///
/// Accepts any number of key-value pairs that will be added as fields to the tracing span.
///
/// # Examples
///
/// ```rust
/// #[log_error(id = "my_function")]
/// async fn my_function() -> Result<(), MyError> {
///     // function body
/// }
///
/// #[log_error(user_id = &self.user_id, action = "decrypt")]
/// async fn decrypt(&self) -> Result<(), MyError> {
///     // function body
/// }
/// ```
#[proc_macro_attribute]
pub fn log_error(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as LogErrorArgs);
    let input = parse_macro_input!(item as ItemFn);
    let vis = &input.vis;
    let sig = &input.sig;
    let block = &input.block;
    let name = &sig.ident;

    let span_creation = if args.fields.is_empty() {
        let name_str = name.to_string();
        quote! {
            let __span = tracing::info_span!(#name_str);
        }
    } else {
        // Generate field assignments for the span
        let field_assignments = args.fields.iter().map(|(key, value)| {
            let var_name = syn::Ident::new(&format!("__span_field_{}", key), key.span());
            quote! {
                let #var_name = format!("{:?}", #value);
            }
        });

        let field_params = args.fields.iter().map(|(key, _value)| {
            let var_name = syn::Ident::new(&format!("__span_field_{}", key), key.span());
            let key_str = key.to_string();
            quote! {
                #key_str = %#var_name
            }
        });

        quote! {
            #(#field_assignments)*
            let __span = tracing::span!(tracing::Level::INFO, "log", #(#field_params),*);
        }
    };

    let result = quote! {
        #vis #sig {
            #span_creation
            let __guard = __span.enter();

            let __log_error_result = (|| {
                #block
            })();

            if let Err(ref e) = __log_error_result {
                tracing::error!(error = %e, "Function returned error");
            }

            drop(__guard);
            __log_error_result
        }
    };

    result.into()
}
