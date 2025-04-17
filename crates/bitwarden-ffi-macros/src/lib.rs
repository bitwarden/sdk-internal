#![doc = include_str!("../README.md")]

mod extern_wasm_channel;

#[proc_macro_attribute]
pub fn extern_wasm_channel(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    match extern_wasm_channel::extern_wasm_channel_internal(args.into(), item.into()) {
        Ok(v) => v.into(),
        Err(e) => proc_macro::TokenStream::from(e.to_compile_error()),
    }
}
