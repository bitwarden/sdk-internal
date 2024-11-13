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
