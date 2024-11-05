#[proc_macro_attribute]
pub fn bitwarden_error(
    _args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    item
}
