mod attribute;
mod basic;
mod flat;
mod full;

#[proc_macro_attribute]
pub fn bitwarden_error(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    attribute::bitwarden_error(args, item)
}

#[proc_macro_derive(BasicError)]
pub fn basic_error(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    basic::derive::basic_error(item)
}

#[proc_macro_derive(FlatError)]
pub fn flat_error(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    flat::derive::flat_error(item)
}
