//! The `impl_wire_*` macros, which implement the wire traits.
//!
//! Defined outside that module so they exist without this crate's `wasm` feature. Like the
//! attribute macros, each one gates what it generates on the calling crate's `wasm` feature, so a
//! call site needs no `cfg` of its own.

/// Implements both traits for a type that crosses as itself: a `#[wasm_bindgen]` handle, an
/// `extern "C"` type, or a primitive wasm_bindgen already understands.
///
/// `#[wasm_object]` calls this for the types it declares.
#[macro_export]
macro_rules! impl_wire_object {
    ($($ty:ty),* $(,)?) => {
        $(
            #[cfg(feature = "wasm")]
            impl $crate::FromWasm for $ty {
                type Wire = $ty;

                fn from_wire(wire: Self::Wire) -> ::core::result::Result<Self, $crate::WireError> {
                    ::core::result::Result::Ok(wire)
                }
            }

            #[cfg(feature = "wasm")]
            impl $crate::ToWasm for $ty {
                type Wire = $ty;

                fn to_wire(self) -> ::core::result::Result<Self::Wire, $crate::WireError> {
                    ::core::result::Result::Ok(self)
                }
            }
        )*
    };
}

/// Implements the traits for a type that crosses as a `String`, so a malformed string is a
/// [`WireError::Parse`](crate::WireError::Parse) rather than a throw from inside `FromWasmAbi`.
///
/// - `impl_wire_string!(T)` parses with `FromStr` and formats with `Display`.
/// - `impl_wire_string!(T, parse = f, format = g)` takes `f: FnOnce(String) -> Result<T, E>` and
///   `g: FnOnce(T) -> String`.
/// - `impl_wire_string!(T, parse = f)` implements only [`FromWasm`](crate::FromWasm), for a type
///   JavaScript never receives.
///
/// Also implements wasm_bindgen's ABI traits through the same conversion, so the type needs no
/// hand-written `WasmDescribe` / `FromWasmAbi` / `IntoWasmAbi`. `from_abi` cannot fail, so it
/// throws on a malformed string.
#[macro_export]
macro_rules! impl_wire_string {
    ($ty:ty $(,)?) => {
        $crate::impl_wire_string!(
            $ty,
            parse = |wire: ::std::string::String| wire.parse::<$ty>(),
            format = |value: $ty| ::std::string::ToString::to_string(&value),
        );
    };
    ($ty:ty, parse = $parse:expr, format = $format:expr $(,)?) => {
        $crate::impl_wire_string!($ty, parse = $parse);

        #[cfg(feature = "wasm")]
        impl $crate::ToWasm for $ty {
            type Wire = ::std::string::String;

            fn to_wire(self) -> ::core::result::Result<Self::Wire, $crate::WireError> {
                ::core::result::Result::Ok($crate::format_wire_string(self, $format))
            }
        }

        #[cfg(feature = "wasm")]
        impl $crate::_macro::wasm_bindgen::convert::IntoWasmAbi for $ty {
            type Abi =
                <::std::string::String as $crate::_macro::wasm_bindgen::convert::IntoWasmAbi>::Abi;

            fn into_abi(self) -> Self::Abi {
                let wire = $crate::_macro::wasm_bindgen::UnwrapThrowExt::unwrap_throw(
                    <$ty as $crate::ToWasm>::to_wire(self),
                );
                $crate::_macro::wasm_bindgen::convert::IntoWasmAbi::into_abi(wire)
            }
        }

        #[cfg(feature = "wasm")]
        impl $crate::_macro::wasm_bindgen::convert::OptionIntoWasmAbi for $ty {
            fn none() -> Self::Abi {
                <::std::string::String as $crate::_macro::wasm_bindgen::convert::OptionIntoWasmAbi>::none()
            }
        }
    };
    ($ty:ty, parse = $parse:expr $(,)?) => {
        #[cfg(feature = "wasm")]
        impl $crate::FromWasm for $ty {
            type Wire = ::std::string::String;

            fn from_wire(wire: Self::Wire) -> ::core::result::Result<Self, $crate::WireError> {
                $crate::parse_wire_string(stringify!($ty), wire, $parse)
            }
        }

        #[cfg(feature = "wasm")]
        impl $crate::_macro::wasm_bindgen::describe::WasmDescribe for $ty {
            fn describe() {
                <::std::string::String as $crate::_macro::wasm_bindgen::describe::WasmDescribe>::describe();
            }
        }

        #[cfg(feature = "wasm")]
        impl $crate::_macro::wasm_bindgen::convert::FromWasmAbi for $ty {
            type Abi =
                <::std::string::String as $crate::_macro::wasm_bindgen::convert::FromWasmAbi>::Abi;

            unsafe fn from_abi(abi: Self::Abi) -> Self {
                // SAFETY: `abi` came from wasm_bindgen as a `String` ABI value, per `Self::Abi`.
                let wire = unsafe {
                    <::std::string::String as $crate::_macro::wasm_bindgen::convert::FromWasmAbi>::from_abi(abi)
                };
                $crate::_macro::wasm_bindgen::UnwrapThrowExt::unwrap_throw(
                    <$ty as $crate::FromWasm>::from_wire(wire),
                )
            }
        }

        #[cfg(feature = "wasm")]
        impl $crate::_macro::wasm_bindgen::convert::OptionFromWasmAbi for $ty {
            fn is_none(abi: &Self::Abi) -> bool {
                <::std::string::String as $crate::_macro::wasm_bindgen::convert::OptionFromWasmAbi>::is_none(abi)
            }
        }
    };
}
