//! How a type crosses the wasm ABI.
//!
//! A proc macro cannot resolve types: seeing the token `CipherView`, `#[wasm_export]` has no way to
//! know whether it is a serde DTO, which crosses as [`Ts<T>`](tsify::Ts), a `#[wasm_bindgen]`
//! handle, which crosses as itself, or a type that crosses as a string. So each type declares its
//! own wire form instead. [`FromWasm::Wire`] and [`ToWasm::Wire`] are what the generated shim puts
//! in its signature, and `#[wasm_record]` / `#[wasm_object]` generate the impls.
//!
//! Conversion happens inside the shim body, where a failure is an ordinary `Err` and destructors
//! run. `#[tsify(from_wasm_abi)]` instead converts inside `FromWasmAbi::from_abi`, which cannot
//! report failure and so calls `wasm_bindgen::throw_str`
//! ([tsify#65](https://github.com/madonoharu/tsify/issues/65)).

use std::fmt::Display;

use bitwarden_error::wasm::{CONVERSION_ERROR_NAME, SdkJsError};
use tsify::{Ts, Tsify};
use wasm_bindgen::JsValue;

/// A value could not be converted across the wasm ABI.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// A string did not parse as the type it crosses as.
    #[error("Failed to parse `{type_name}`: {message}")]
    Parse {
        /// The type the string was parsed as.
        type_name: &'static str,
        /// The parser's error message.
        message: String,
    },
    /// A serde DTO did not convert to or from its `Ts<T>` form.
    #[error(transparent)]
    Serde(#[from] tsify::Error),
}

/// A type that can be received from JavaScript, crossing the ABI as [`Self::Wire`].
pub trait FromWasm: Sized {
    /// The type JavaScript actually passes.
    type Wire;

    /// Recovers the Rust value from the wire value.
    fn from_wire(wire: Self::Wire) -> Result<Self, WireError>;
}

/// A type that can be handed to JavaScript, crossing the ABI as [`Self::Wire`].
pub trait ToWasm {
    /// The type JavaScript actually receives.
    type Wire;

    /// Converts the Rust value into the wire value.
    fn to_wire(self) -> Result<Self::Wire, WireError>;
}

/// Runs an `impl_wire_string!` parser. A function rather than inline macro code so the closure's
/// argument type is inferred.
#[doc(hidden)]
pub fn parse_wire_string<T, E: Display>(
    type_name: &'static str,
    wire: String,
    parse: impl FnOnce(String) -> Result<T, E>,
) -> Result<T, WireError> {
    parse(wire).map_err(|err| WireError::Parse {
        type_name,
        message: err.to_string(),
    })
}

/// Runs an `impl_wire_string!` formatter; see [`parse_wire_string`].
#[doc(hidden)]
pub fn format_wire_string<T>(value: T, format: impl FnOnce(T) -> String) -> String {
    format(value)
}

// The closed set of types wasm_bindgen carries natively. Being absent from it is a missing-impl
// compile error at the use site.
crate::impl_wire_object!(
    bool,
    char,
    f32,
    f64,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
    (),
    String,
    JsValue,
);

/// `Vec<T>` crosses as a vector of `T`'s wire type, so `Vec<u8>` stays `Vec<u8>` and reaches
/// JavaScript as a `Uint8Array`, while `Vec<CipherView>` becomes `Vec<Ts<CipherView>>`.
///
/// `Ts` sits on the element, never the vector: `Ts<Vec<T>>` is not something tsify supports.
impl<T: FromWasm> FromWasm for Vec<T> {
    type Wire = Vec<T::Wire>;

    fn from_wire(wire: Self::Wire) -> Result<Self, WireError> {
        wire.into_iter().map(T::from_wire).collect()
    }
}

impl<T: ToWasm> ToWasm for Vec<T> {
    type Wire = Vec<T::Wire>;

    fn to_wire(self) -> Result<Self::Wire, WireError> {
        self.into_iter().map(T::to_wire).collect()
    }
}

impl<T: FromWasm> FromWasm for Option<T> {
    type Wire = Option<T::Wire>;

    fn from_wire(wire: Self::Wire) -> Result<Self, WireError> {
        wire.map(T::from_wire).transpose()
    }
}

impl<T: ToWasm> ToWasm for Option<T> {
    type Wire = Option<T::Wire>;

    fn to_wire(self) -> Result<Self::Wire, WireError> {
        self.map(T::to_wire).transpose()
    }
}

/// Lets a shim name `Ts<T>` in a signature it was handed already-wrapped, for the hand-written
/// `extern "C"` blocks that construct the wrapper themselves.
impl<T: Tsify> FromWasm for Ts<T> {
    type Wire = Ts<T>;

    fn from_wire(wire: Self::Wire) -> Result<Self, WireError> {
        Ok(wire)
    }
}

impl<T: Tsify> ToWasm for Ts<T> {
    type Wire = Ts<T>;

    fn to_wire(self) -> Result<Self::Wire, WireError> {
        Ok(self)
    }
}

/// Stands in for the error of a shim whose underlying method cannot fail.
#[derive(Debug)]
pub enum Never {}

impl From<Never> for JsValue {
    fn from(value: Never) -> Self {
        match value {}
    }
}

/// Error of a generated shim.
///
/// `Inner` reaches JavaScript through `E`'s own `From<E> for JsValue`, so a `bitwarden_error` type
/// keeps the `name` and `variant` it already had. Shims for infallible methods use the default `E`,
/// leaving `Conversion` as the only reachable variant.
#[derive(Debug)]
pub enum TsError<E = Never> {
    /// The underlying method failed.
    Inner(E),
    /// A value could not be converted across the boundary.
    Conversion(WireError),
}

impl<E: Into<JsValue>> From<TsError<E>> for JsValue {
    fn from(value: TsError<E>) -> Self {
        match value {
            TsError::Inner(inner) => inner.into(),
            TsError::Conversion(err) => {
                let js_error = SdkJsError::new(err.to_string());
                js_error.set_name(CONVERSION_ERROR_NAME.to_owned());
                js_error.into()
            }
        }
    }
}

/// The error a `#[wasm_import]` wrapper returns when an argument does not convert, matching what a
/// `#[wasm_export]` shim throws for the same failure.
#[doc(hidden)]
pub fn import_conversion_error(err: WireError) -> JsValue {
    TsError::<Never>::Conversion(err).into()
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;

    #[derive(Debug, PartialEq)]
    struct Digit(u8);

    impl std::str::FromStr for Digit {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            s.parse()
                .map(Digit)
                .map_err(|_| format!("not a digit: {s}"))
        }
    }

    impl Display for Digit {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    crate::impl_wire_string!(Digit);

    struct Shout(String);

    crate::impl_wire_string!(
        Shout,
        parse = |wire: String| Ok::<_, Infallible>(Shout(wire.to_uppercase())),
        format = |value: Shout| value.0,
    );

    struct InputOnly(String);

    crate::impl_wire_string!(
        InputOnly,
        parse = |wire| Ok::<_, Infallible>(InputOnly(wire))
    );

    #[test]
    fn default_form_round_trips() {
        let digit = Digit::from_wire("7".to_owned()).unwrap();
        assert_eq!(digit, Digit(7));
        assert_eq!(digit.to_wire().unwrap(), "7");
    }

    #[test]
    fn malformed_string_is_a_parse_error() {
        let err = Digit::from_wire("x".to_owned()).unwrap_err();
        assert_eq!(err.to_string(), "Failed to parse `Digit`: not a digit: x");
    }

    #[test]
    fn custom_form_uses_the_given_functions() {
        let shout = Shout::from_wire("hi".to_owned()).unwrap();
        assert_eq!(shout.to_wire().unwrap(), "HI");
        assert_eq!(InputOnly::from_wire("hi".to_owned()).unwrap().0, "hi");
    }

    #[test]
    fn a_bad_element_fails_the_whole_vec() {
        let wire = vec!["1".to_owned(), "x".to_owned()];
        assert!(Vec::<Digit>::from_wire(wire).is_err());
        assert_eq!(Option::<Digit>::from_wire(None).unwrap(), None);
    }
}
