use crate::SensitiveString;

// A list of secret value type aliases
/// A master password. Wrapped to prevent accidental logging.
pub type MasterPassword = SensitiveString;
/// A PIN. Wrapped to prevent accidental logging.
pub type Pin = SensitiveString;

// Tsify/wasm-bindgen emit the type alias name verbatim when these are used as fields, so we must
// declare matching TypeScript types. They are structurally identical to `SensitiveString`.
#[cfg(feature = "wasm")]
const _: () = {
    use wasm_bindgen::prelude::wasm_bindgen;

    #[wasm_bindgen(typescript_custom_section)]
    const TS_CUSTOM_TYPES: &'static str = r#"
export type MasterPassword = SensitiveString;
export type Pin = SensitiveString;
"#;
};
