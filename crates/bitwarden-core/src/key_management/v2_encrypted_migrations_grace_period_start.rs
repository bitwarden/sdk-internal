use chrono::{DateTime, Utc};

/// Records when the user first became eligible for v2 encrypted migrations.
#[bitwarden_ffi::wasm_record]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(transparent)]
pub struct V2EncryptedMigrationsGracePeriodStart(
    #[cfg_attr(feature = "wasm", tsify(type = "DateTime<Utc>"))] pub DateTime<Utc>,
);

#[cfg(feature = "wasm")]
impl TryFrom<wasm_bindgen::JsValue> for V2EncryptedMigrationsGracePeriodStart {
    type Error = serde_wasm_bindgen::Error;

    fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
        serde_wasm_bindgen::from_value(value)
    }
}

#[cfg(feature = "uniffi")]
uniffi::custom_newtype!(V2EncryptedMigrationsGracePeriodStart, DateTime<Utc>);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_as_an_rfc3339_string() {
        let start = "2026-08-27T12:34:56.789Z".parse().unwrap();
        let value = V2EncryptedMigrationsGracePeriodStart(start);

        let serialized = serde_json::to_value(&value).unwrap();
        assert_eq!(serialized, serde_json::json!("2026-08-27T12:34:56.789Z"));

        let deserialized = serde_json::from_value(serialized).unwrap();
        assert_eq!(value, deserialized);
    }
}
