/// Feature flags for the Bitwarden SDK client.
#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct Flags {
    /// Enable cipher key encryption within the `CipherClient`
    #[serde(default, rename = "enableCipherKeyEncryption")]
    pub enable_cipher_key_encryption: bool,
}

impl Flags {
    /// Create a new `Flags` instance from a map of flag names and values.
    pub fn load_from_map(map: std::collections::HashMap<String, bool>) -> Self {
        let map = map
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::Bool(v)))
            .collect();
        serde_json::from_value(serde_json::Value::Object(map)).expect("Valid map")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_empty_map() {
        let map = std::collections::HashMap::new();
        let flags = Flags::load_from_map(map);
        assert!(!flags.enable_cipher_key_encryption);
    }

    #[test]
    fn test_load_valid_map() {
        let mut map = std::collections::HashMap::new();
        map.insert("enableCipherKeyEncryption".into(), true);
        let flags = Flags::load_from_map(map);
        assert!(flags.enable_cipher_key_encryption);
    }

    #[test]
    fn test_load_invalid_map() {
        let mut map = std::collections::HashMap::new();
        map.insert("thisIsNotAFlag".into(), true);
        let flags = Flags::load_from_map(map);
        assert!(!flags.enable_cipher_key_encryption);
    }
}
