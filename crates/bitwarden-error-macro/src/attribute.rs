use darling::{FromMeta, ast::NestedMeta};
use quote::format_ident;

use crate::args::{BitwardenErrorArgs, BitwardenErrorType};

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

    let args = match BitwardenErrorArgs::from_list(&attr_args) {
        Ok(params) => params,
        Err(error) => {
            return proc_macro::TokenStream::from(error.write_errors());
        }
    };

    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let type_identifier = &input.ident;
    let export_as_identifier = &args
        .export_as
        .as_ref()
        .map(|export_as| format_ident!("{}", export_as))
        .unwrap_or(input.ident.clone());

    match args.error_type {
        BitwardenErrorType::Basic => crate::basic::attribute::bitwarden_error_basic(
            &input,
            type_identifier,
            export_as_identifier,
        ),
        BitwardenErrorType::Flat => crate::flat::attribute::bitwarden_error_flat(
            &input,
            type_identifier,
            export_as_identifier,
        ),
        BitwardenErrorType::Full => crate::full::attribute::bitwarden_error_full(
            &input,
            type_identifier,
            export_as_identifier,
        ),
    }
}
