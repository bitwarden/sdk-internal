//! How the macros name a type's wire form in a generated signature.

use proc_macro2::TokenStream;
use quote::quote;
use syn::Type;

/// The type JavaScript passes for a parameter of type `ty`.
///
/// `#[wasm_record]` and `#[wasm_object]` implement `FromWasm` at each type's declaration site, so
/// this resolves to `Ts<T>` for a serde DTO and to `T` for a `#[wasm_bindgen]` handle. A type that
/// has declared neither is a missing-impl error naming the site.
pub(crate) fn from_wire_type(ty: &Type) -> TokenStream {
    quote!(<#ty as ::bitwarden_ffi::FromWasm>::Wire)
}

/// The type JavaScript receives for a value of type `ty`.
pub(crate) fn to_wire_type(ty: &Type) -> TokenStream {
    quote!(<#ty as ::bitwarden_ffi::ToWasm>::Wire)
}

/// Whether a value crosses the ABI as written, with no wire conversion.
///
/// References only: `Ts<T>` is passed by value, so a reference can never be wrapped. Covers `&[u8]`
/// and borrowed handles such as `&JsCommunicationBackend`.
pub(crate) fn crosses_bare(ty: &Type) -> bool {
    matches!(ty, Type::Reference(_))
}

/// `Result<R, E>` -> `(R, E)`.
pub(crate) fn split_result(ty: &Type) -> Option<(&Type, &Type)> {
    let Type::Path(path) = ty else { return None };
    let segment = path.path.segments.last()?;
    if segment.ident != "Result" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    let mut types = args.args.iter().filter_map(|arg| match arg {
        syn::GenericArgument::Type(ty) => Some(ty),
        _ => None,
    });
    Some((types.next()?, types.next()?))
}
