#![doc = include_str!("../README.md")]

mod wasm_ipc;

#[proc_macro_attribute]
pub fn bitwarden_wasm_ipc_channel(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    match wasm_ipc::bitwarden_wasm_ipc_channel_internal(args, item) {
        Ok(v) => v,
        Err(e) => proc_macro::TokenStream::from(e.to_compile_error()),
    }
}
