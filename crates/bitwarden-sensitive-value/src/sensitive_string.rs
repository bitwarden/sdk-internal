use core::fmt;

use crate::{Sensitive, SensitiveSlice, sensitive::ExposeSensitive};

/// FFI-friendly concrete wrapper around a sensitive `String`. This is the type exposed across the
/// UniFFI / WASM boundary; bindings see it as an opaque tagged string. `Debug` and `Display`
/// delegate to the inner [`Sensitive`], so output is redacted unless `dangerous-crypto-debug`
/// is enabled.
pub struct SensitiveString(Sensitive<String>);

impl From<&str> for Sensitive<String> {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl SensitiveString {
    /// Borrow the secret as a zero-copy [`SensitiveSlice`] over its UTF-8 bytes. The returned
    /// slice borrows from this value and stays wrapped, so the bytes are never exposed and the
    /// borrow cannot outlive `self`.
    pub fn as_bytes(&self) -> SensitiveSlice<'_> {
        // EXPOSE: We borrow the inner string only to immediately re-wrap its bytes in another
        // `Sensitive`, so the secret is never actually exposed to logging.
        Sensitive::from(self.0.expose().as_bytes())
    }
}

impl<T: fmt::Debug> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "dangerous-crypto-debug")]
        {
            self.0.fmt(f)
        }
        #[cfg(not(feature = "dangerous-crypto-debug"))]
        {
            f.write_str("[REDACTED]")
        }
    }
}

impl<T: fmt::Display> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(feature = "dangerous-crypto-debug")]
        {
            self.0.fmt(f)
        }
        #[cfg(not(feature = "dangerous-crypto-debug"))]
        {
            f.write_str("[REDACTED]")
        }
    }
}

impl ExposeSensitive for SensitiveString {
    type Exposed = String;

    fn expose(&self) -> &Self::Exposed {
        self.0.expose()
    }

    fn expose_owned(self) -> Self::Exposed {
        self.0.expose_owned()
    }
}

impl From<&str> for SensitiveString {
    fn from(value: &str) -> Self {
        Self(Sensitive::from(value.to_string()))
    }
}

impl From<String> for SensitiveString {
    fn from(value: String) -> Self {
        Self(Sensitive::from(value))
    }
}

impl PartialEq for SensitiveString {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl serde::Serialize for SensitiveString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for SensitiveString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(Sensitive::<String>::deserialize(deserializer)?))
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(feature = "uniffi")]
uniffi::custom_type!(SensitiveString, String, {
    try_lift: |val| Ok(SensitiveString::from(val)),
    lower: |obj| obj.expose().to_string(),
});

#[cfg(feature = "wasm")]
const _: () = {
    use wasm_bindgen::{
        JsValue, UnwrapThrowExt,
        convert::{FromWasmAbi, IntoWasmAbi, OptionFromWasmAbi, OptionIntoWasmAbi},
        prelude::wasm_bindgen,
    };

    #[wasm_bindgen(typescript_custom_section)]
    const TS_CUSTOM_TYPES: &'static str = r#"
export type SensitiveString = Tagged<string, "SensitiveString">;
"#;

    // The value still crosses the WASM boundary as a plain JS string, but we describe it as a
    // named externref so generated `.d.ts` signatures read `SensitiveString` instead of the bare
    // `string` produced when delegating to `String::describe`. The name must match the type alias
    // declared in `TS_CUSTOM_TYPES` above.
    impl wasm_bindgen::describe::WasmDescribe for SensitiveString {
        fn describe() {
            use wasm_bindgen::describe::*;
            // wasm-bindgen's descriptor interpreter only understands a flat sequence of constant
            // `inform` calls (no loops or comparisons), so the name "SensitiveString" is emitted
            // one character at a time. This must match the type alias in `TS_CUSTOM_TYPES` above.
            inform(NAMED_EXTERNREF);
            inform(15); // "SensitiveString".len()
            inform('S' as u32);
            inform('e' as u32);
            inform('n' as u32);
            inform('s' as u32);
            inform('i' as u32);
            inform('t' as u32);
            inform('i' as u32);
            inform('v' as u32);
            inform('e' as u32);
            inform('S' as u32);
            inform('t' as u32);
            inform('r' as u32);
            inform('i' as u32);
            inform('n' as u32);
            inform('g' as u32);
        }
    }

    impl FromWasmAbi for SensitiveString {
        type Abi = <JsValue as FromWasmAbi>::Abi;

        unsafe fn from_abi(abi: Self::Abi) -> Self {
            let value = unsafe { JsValue::from_abi(abi) };
            let string = value
                .as_string()
                .expect_throw("SensitiveString JsValue is not a string");
            SensitiveString::from(string)
        }
    }

    impl OptionFromWasmAbi for SensitiveString {
        fn is_none(abi: &Self::Abi) -> bool {
            <JsValue as OptionFromWasmAbi>::is_none(abi)
        }
    }

    impl IntoWasmAbi for SensitiveString {
        type Abi = <JsValue as IntoWasmAbi>::Abi;

        fn into_abi(self) -> Self::Abi {
            JsValue::from(self.expose_owned()).into_abi()
        }
    }

    impl OptionIntoWasmAbi for SensitiveString {
        fn none() -> Self::Abi {
            <JsValue as OptionIntoWasmAbi>::none()
        }
    }

    impl From<SensitiveString> for JsValue {
        fn from(value: SensitiveString) -> Self {
            JsValue::from(value.expose_owned())
        }
    }

    impl TryFrom<JsValue> for SensitiveString {
        type Error = &'static str;

        fn try_from(value: JsValue) -> Result<Self, Self::Error> {
            value
                .as_string()
                .map(SensitiveString::from)
                .ok_or("SensitiveString JsValue is not a string")
        }
    }
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_and_from_string_are_equivalent() {
        assert_eq!(
            SensitiveString::from("secret"),
            SensitiveString::from("secret".to_string())
        );
    }

    #[test]
    fn partial_eq_compares_inner_values() {
        assert_eq!(
            SensitiveString::from("secret"),
            SensitiveString::from("secret")
        );
        assert_ne!(
            SensitiveString::from("secret"),
            SensitiveString::from("other")
        );
    }

    #[test]
    fn expose_returns_inner_string() {
        let sensitive = SensitiveString::from("secret");
        assert_eq!(sensitive.expose(), "secret");
        assert_eq!(sensitive.expose_owned(), "secret");
    }

    #[test]
    fn as_bytes_borrows_utf8_bytes() {
        let sensitive = SensitiveString::from("secret");
        let bytes = sensitive.as_bytes();
        assert_eq!(bytes.expose_owned(), b"secret");
    }

    #[cfg(not(feature = "dangerous-crypto-debug"))]
    #[test]
    fn debug_is_redacted() {
        let sensitive = SensitiveString::from("secret");
        assert_eq!(format!("{sensitive:?}"), "[REDACTED]");
    }

    #[cfg(not(feature = "dangerous-crypto-debug"))]
    #[test]
    fn display_is_redacted() {
        let sensitive = SensitiveString::from("secret");
        assert_eq!(format!("{sensitive}"), "[REDACTED]");
    }

    #[test]
    fn serde_json_round_trips_transparently() {
        let sensitive = SensitiveString::from("secret");

        let serialized = serde_json::to_string(&sensitive).unwrap();
        assert_eq!(serialized, "\"secret\"");

        let deserialized: SensitiveString = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, sensitive);
    }
}
