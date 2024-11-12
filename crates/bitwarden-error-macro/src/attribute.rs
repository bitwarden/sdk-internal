use darling::{ast::NestedMeta, FromMeta};

#[derive(FromMeta)]
struct BitwardenErrorArgs {
    #[darling(flatten)]
    error_type: BitwardenErrorType,
}

#[derive(FromMeta)]
enum BitwardenErrorType {
    /// The error is going to be converted into a string using the `ToString` trait
    #[darling(rename = "basic")]
    Basic,

    /// The error is going to be converted into a flat error using the `FlatError` trait
    #[darling(rename = "flat")]
    Flat,

    /// The entire error stack is going to be made available using `serde`
    #[darling(rename = "full")]
    Full,
}

pub(crate) fn bitwarden_error(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let attr_args = match NestedMeta::parse_meta_list(args.into()) {
        Ok(v) => v,
        Err(e) => {
            return proc_macro::TokenStream::from(darling::Error::from(e).write_errors());
        }
    };

    let BitwardenErrorArgs { error_type } = match BitwardenErrorArgs::from_list(&attr_args) {
        Ok(params) => params,
        Err(error) => {
            return proc_macro::TokenStream::from(error.write_errors());
        }
    };

    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    match error_type {
        BitwardenErrorType::Basic => crate::basic::attribute::bitwarden_error_basic(&input),
        BitwardenErrorType::Flat => crate::flat::attribute::bitwarden_error_flat(&input),
        BitwardenErrorType::Full => crate::full::attribute::bitwarden_error_full(&input),
    }
}
