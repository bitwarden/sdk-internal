//! How a type crosses the wasm ABI.
//!
//! A proc macro cannot resolve types: seeing the token `CipherView`, `#[wasm_export]` has no way to
//! know whether it is a serde DTO, which crosses as [`Ts<T>`](tsify::Ts), or a `#[wasm_bindgen]`
//! handle, which crosses as itself. So each type declares its own wire form instead.
//! [`FromWasm::Wire`] and [`ToWasm::Wire`] are what the generated shim puts in its signature, and
//! `#[wasm_record]` / `#[wasm_object]` generate the impls, so no type implements them by hand.
//!
//! Conversion happens inside the shim body, where a failure is an ordinary `Err` and destructors
//! run. `#[tsify(from_wasm_abi)]` instead converts inside `FromWasmAbi::from_abi`, which cannot
//! report failure and so calls `wasm_bindgen::throw_str`
//! ([tsify#65](https://github.com/madonoharu/tsify/issues/65)).

use bitwarden_error::wasm::{CONVERSION_ERROR_NAME, SdkJsError};
use tsify::{Error, Ts, Tsify};
use wasm_bindgen::JsValue;

/// A type that can be received from JavaScript, crossing the ABI as [`Self::Wire`].
pub trait FromWasm: Sized {
    /// The type JavaScript actually passes.
    type Wire;

    /// Recovers the Rust value from the wire value.
    fn from_wire(wire: Self::Wire) -> Result<Self, Error>;
}

/// A type that can be handed to JavaScript, crossing the ABI as [`Self::Wire`].
pub trait ToWasm {
    /// The type JavaScript actually receives.
    type Wire;

    /// Converts the Rust value into the wire value.
    fn to_wire(self) -> Result<Self::Wire, Error>;
}

/// Implements both traits for a serde DTO, which crosses as `Ts<Self>`.
///
/// Used by `#[wasm_record]`; there is no reason to call it directly.
#[macro_export]
macro_rules! impl_wire_record {
    ($ty:ty) => {
        impl $crate::FromWasm for $ty {
            type Wire = $crate::Ts<$ty>;

            fn from_wire(wire: Self::Wire) -> ::core::result::Result<Self, $crate::TsifyError> {
                wire.to_rust()
            }
        }

        impl $crate::ToWasm for $ty {
            type Wire = $crate::Ts<$ty>;

            fn to_wire(self) -> ::core::result::Result<Self::Wire, $crate::TsifyError> {
                $crate::Ts::from_rust(&self)
            }
        }
    };
}

/// Implements both traits for a type that crosses as itself: a `#[wasm_bindgen]` handle, or a
/// primitive wasm_bindgen already understands.
///
/// Used by `#[wasm_object]` and for the built-in impls below.
#[macro_export]
macro_rules! impl_wire_object {
    ($($ty:ty),* $(,)?) => {
        $(
            impl $crate::FromWasm for $ty {
                type Wire = $ty;

                fn from_wire(wire: Self::Wire) -> ::core::result::Result<Self, $crate::TsifyError> {
                    ::core::result::Result::Ok(wire)
                }
            }

            impl $crate::ToWasm for $ty {
                type Wire = $ty;

                fn to_wire(self) -> ::core::result::Result<Self::Wire, $crate::TsifyError> {
                    ::core::result::Result::Ok(self)
                }
            }
        )*
    };
}

// The closed set of types wasm_bindgen carries natively. Being absent from it is a missing-impl
// compile error at the use site.
impl_wire_object!(
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

    fn from_wire(wire: Self::Wire) -> Result<Self, Error> {
        wire.into_iter().map(T::from_wire).collect()
    }
}

impl<T: ToWasm> ToWasm for Vec<T> {
    type Wire = Vec<T::Wire>;

    fn to_wire(self) -> Result<Self::Wire, Error> {
        self.into_iter().map(T::to_wire).collect()
    }
}

impl<T: FromWasm> FromWasm for Option<T> {
    type Wire = Option<T::Wire>;

    fn from_wire(wire: Self::Wire) -> Result<Self, Error> {
        wire.map(T::from_wire).transpose()
    }
}

impl<T: ToWasm> ToWasm for Option<T> {
    type Wire = Option<T::Wire>;

    fn to_wire(self) -> Result<Self::Wire, Error> {
        self.map(T::to_wire).transpose()
    }
}

/// Lets a shim name `Ts<T>` in a signature it was handed already-wrapped, for the hand-written
/// `extern "C"` blocks that construct the wrapper themselves.
impl<T: Tsify> FromWasm for Ts<T> {
    type Wire = Ts<T>;

    fn from_wire(wire: Self::Wire) -> Result<Self, Error> {
        Ok(wire)
    }
}

impl<T: Tsify> ToWasm for Ts<T> {
    type Wire = Ts<T>;

    fn to_wire(self) -> Result<Self::Wire, Error> {
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
    Conversion(tsify::Error),
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
