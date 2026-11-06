use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use syn::{Attribute, GenericArgument, PathArguments, ReturnType, Signature, Type};

use crate::attrs;

/// Declares the TypeScript type of a method's `BwStream` return on the method, unless it declares
/// one itself.
pub(crate) fn declare_return_type(
    method_attrs: &mut Vec<Attribute>,
    sig: &Signature,
) -> syn::Result<()> {
    let declared = method_attrs
        .iter()
        .filter_map(attrs::wasm_bindgen_args)
        .flatten()
        .any(|meta| meta.path().is_ident("unchecked_return_type"));
    if !declared && let Some(ts) = stream_return_type(&sig.output)? {
        method_attrs.push(syn::parse_quote!(
            #[cfg_attr(feature = "wasm", wasm_bindgen(unchecked_return_type = #ts))]
        ));
    }
    Ok(())
}

/// Declares the TypeScript type of a free function's `BwStream` return in the arguments forwarded
/// to its `#[wasm_bindgen]`, unless they declare one.
pub(crate) fn forward_return_type(forwarded: &mut attrs::Args, sig: &Signature) -> syn::Result<()> {
    let declared = forwarded
        .iter()
        .any(|meta| meta.path().is_ident("unchecked_return_type"));
    if !declared && let Some(ts) = stream_return_type(&sig.output)? {
        forwarded.push(syn::parse_quote!(unchecked_return_type = #ts));
    }
    Ok(())
}

/// The TypeScript type of a return type that is a `BwStream`, or `None` for any other return type.
///
/// wasm_bindgen types a `BwStream` as `any`, because the items it carries are generic. The type
/// is built from the tokens instead, so it cannot drift from the Rust type. A top-level `Result`
/// is unwrapped first: wasm_bindgen throws its `Err`, so only the `Ok` type reaches JavaScript.
/// An `async` function needs no `Promise<..>` here, as wasm_bindgen wraps the type it is given.
///
/// Fails on a `BwStream` that is nested anywhere else, or that carries a type with no confident
/// mapping, so the caller declares the type rather than getting a wrong one.
fn stream_return_type(output: &ReturnType) -> syn::Result<Option<String>> {
    let ReturnType::Type(_, ty) = output else {
        return Ok(None);
    };
    if !mentions_stream(ty.to_token_stream()) {
        return Ok(None);
    }

    let returned: &Type = match generic_args(ty, "Result").as_deref() {
        Some([ok, _]) => ok,
        _ => ty,
    };
    match generic_args(returned, "BwStream").as_deref() {
        Some([item]) => Ok(Some(format!("AsyncIterable<{}>", stream_item(item)?))),
        _ => Err(unmappable(ty)),
    }
}

/// A stream item, where a `Result` is handed out as a `BwResult` object rather than thrown.
fn stream_item(ty: &Type) -> syn::Result<String> {
    match generic_args(ty, "Result").as_deref() {
        Some([ok, err]) => Ok(format!("BwResult<{}, {}>", ts_type(ok)?, ts_type(err)?)),
        _ => ts_type(ty),
    }
}

/// The TypeScript type of a value converted with `Into<JsValue>`, as wasm_bindgen types it.
fn ts_type(ty: &Type) -> syn::Result<String> {
    match ty {
        Type::Group(group) => ts_type(&group.elem),
        Type::Paren(paren) => ts_type(&paren.elem),
        Type::Reference(reference) if is_ident(&reference.elem, "str") => Ok("string".to_owned()),
        Type::Path(path) if path.qself.is_none() => {
            let segment = path.path.segments.last().ok_or_else(|| unmappable(ty))?;
            let name = segment.ident.to_string();
            match (name.as_str(), type_args(&segment.arguments).as_deref()) {
                ("Box", Some([inner])) => ts_type(inner),
                ("Option", Some([inner])) => Ok(format!("{} | undefined", ts_type(inner)?)),
                ("BwStream", Some([item])) => Ok(format!("AsyncIterable<{}>", stream_item(item)?)),
                ("Vec", Some([inner])) => match typed_array(inner) {
                    Some(array) => Ok(array.to_owned()),
                    None => {
                        let element = ts_type(inner)?;
                        if element.contains('|') {
                            Ok(format!("({element})[]"))
                        } else {
                            Ok(format!("{element}[]"))
                        }
                    }
                },
                (_, Some(_)) => Err(unmappable(ty)),
                ("String" | "str" | "char", None) => Ok("string".to_owned()),
                ("bool", None) => Ok("boolean".to_owned()),
                (
                    "u8" | "i8" | "u16" | "i16" | "u32" | "i32" | "usize" | "isize" | "f32" | "f64",
                    None,
                ) => Ok("number".to_owned()),
                ("u64" | "i64" | "u128" | "i128", None) => Ok("bigint".to_owned()),
                ("JsValue", None) => Ok("any".to_owned()),
                // The JavaScript name of `Self` is not known here.
                ("Self", None) => Err(unmappable(ty)),
                // A `#[wasm_record]` or `#[wasm_object]` type, whose TypeScript name is its Rust
                // name unless it is renamed.
                (_, None) => Ok(name),
            }
        }
        _ => Err(unmappable(ty)),
    }
}

/// The typed array wasm_bindgen converts a `Vec` of a number type into.
fn typed_array(element: &Type) -> Option<&'static str> {
    let Type::Path(path) = element else {
        return None;
    };
    Some(match path.path.get_ident()?.to_string().as_str() {
        "u8" => "Uint8Array",
        "i8" => "Int8Array",
        "u16" => "Uint16Array",
        "i16" => "Int16Array",
        "u32" | "usize" => "Uint32Array",
        "i32" | "isize" => "Int32Array",
        "u64" => "BigUint64Array",
        "i64" => "BigInt64Array",
        "f32" => "Float32Array",
        "f64" => "Float64Array",
        _ => return None,
    })
}

/// The type arguments of `ty` if it is a path ending in `name`, as in `name<..>`.
fn generic_args<'a>(ty: &'a Type, name: &str) -> Option<Vec<&'a Type>> {
    let Type::Path(path) = ty else { return None };
    let segment = path.path.segments.last()?;
    if path.qself.is_some() || segment.ident != name {
        return None;
    }
    type_args(&segment.arguments)
}

/// The type arguments in `<..>`, or `None` if there are none or any argument is not a type.
fn type_args(arguments: &PathArguments) -> Option<Vec<&Type>> {
    let PathArguments::AngleBracketed(arguments) = arguments else {
        return None;
    };
    arguments
        .args
        .iter()
        .map(|arg| match arg {
            GenericArgument::Type(ty) => Some(ty),
            _ => None,
        })
        .collect()
}

fn is_ident(ty: &Type, name: &str) -> bool {
    matches!(ty, Type::Path(path) if path.qself.is_none() && path.path.is_ident(name))
}

/// Whether `BwStream` appears anywhere in the tokens.
fn mentions_stream(tokens: TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Ident(ident) => ident == "BwStream",
        TokenTree::Group(group) => mentions_stream(group.stream()),
        _ => false,
    })
}

fn unmappable(ty: &Type) -> syn::Error {
    syn::Error::new_spanned(
        ty,
        format!(
            "#[wasm_export] cannot infer the TypeScript type of `{}`; declare it with \
             #[wasm_bindgen(unchecked_return_type = \"...\")]",
            ty.to_token_stream()
        ),
    )
}

#[cfg(test)]
mod tests {
    use quote::quote;

    use super::*;

    /// The inferred type of the return type written after `fn f()`.
    fn infer(output: TokenStream) -> syn::Result<Option<String>> {
        stream_return_type(&syn::parse2(output).expect("a return type"))
    }

    fn infer_ok(output: TokenStream) -> String {
        infer(output)
            .expect("a mappable type")
            .expect("a stream type")
    }

    #[test]
    fn leaves_a_return_type_without_a_stream_alone() {
        assert_eq!(infer(quote!(-> Vec<Cipher>)).unwrap(), None);
        assert_eq!(infer(quote!(-> Result<Cipher, Error>)).unwrap(), None);
        assert_eq!(infer(quote!()).unwrap(), None);
    }

    #[test]
    fn types_a_stream_as_an_async_iterable() {
        assert_eq!(
            infer_ok(quote!(-> BwStream<Cipher>)),
            "AsyncIterable<Cipher>"
        );
        assert_eq!(
            infer_ok(quote!(-> bitwarden_ffi::BwStream<crate::Cipher>)),
            "AsyncIterable<Cipher>"
        );
    }

    #[test]
    fn types_result_items_as_bw_results() {
        assert_eq!(
            infer_ok(quote!(-> BwStream<Result<CipherListView, Box<Cipher>>>)),
            "AsyncIterable<BwResult<CipherListView, Cipher>>"
        );
    }

    #[test]
    fn unwraps_a_top_level_result_which_wasm_bindgen_throws() {
        assert_eq!(
            infer_ok(quote!(-> Result<BwStream<Cipher>, StreamError>)),
            "AsyncIterable<Cipher>"
        );
    }

    #[test]
    fn maps_primitives_as_wasm_bindgen_does() {
        assert_eq!(
            infer_ok(quote!(-> BwStream<String>)),
            "AsyncIterable<string>"
        );
        assert_eq!(
            infer_ok(quote!(-> BwStream<&'static str>)),
            "AsyncIterable<string>"
        );
        assert_eq!(infer_ok(quote!(-> BwStream<char>)), "AsyncIterable<string>");
        assert_eq!(
            infer_ok(quote!(-> BwStream<bool>)),
            "AsyncIterable<boolean>"
        );
        assert_eq!(infer_ok(quote!(-> BwStream<JsValue>)), "AsyncIterable<any>");
        for number in [
            "u8", "i8", "u16", "i16", "u32", "i32", "usize", "isize", "f32", "f64",
        ] {
            let ty: TokenStream = format!("-> BwStream<{number}>").parse().unwrap();
            assert_eq!(infer_ok(ty), "AsyncIterable<number>", "{number}");
        }
        for big in ["u64", "i64", "u128", "i128"] {
            let ty: TokenStream = format!("-> BwStream<{big}>").parse().unwrap();
            assert_eq!(infer_ok(ty), "AsyncIterable<bigint>", "{big}");
        }
    }

    #[test]
    fn maps_containers() {
        assert_eq!(
            infer_ok(quote!(-> BwStream<Box<Cipher>>)),
            "AsyncIterable<Cipher>"
        );
        assert_eq!(
            infer_ok(quote!(-> BwStream<Vec<Cipher>>)),
            "AsyncIterable<Cipher[]>"
        );
        assert_eq!(
            infer_ok(quote!(-> BwStream<Option<Cipher>>)),
            "AsyncIterable<Cipher | undefined>"
        );
        assert_eq!(
            infer_ok(quote!(-> BwStream<Vec<Option<String>>>)),
            "AsyncIterable<(string | undefined)[]>"
        );
        assert_eq!(
            infer_ok(quote!(-> BwStream<BwStream<Cipher>>)),
            "AsyncIterable<AsyncIterable<Cipher>>"
        );
    }

    #[test]
    fn maps_a_vec_of_numbers_to_a_typed_array() {
        assert_eq!(
            infer_ok(quote!(-> BwStream<Vec<u8>>)),
            "AsyncIterable<Uint8Array>"
        );
        assert_eq!(
            infer_ok(quote!(-> BwStream<Vec<u64>>)),
            "AsyncIterable<BigUint64Array>"
        );
        assert_eq!(
            infer_ok(quote!(-> BwStream<Vec<f64>>)),
            "AsyncIterable<Float64Array>"
        );
    }

    #[test]
    fn rejects_what_it_cannot_map() {
        for output in [
            quote!(-> BwStream<(u8, u8)>),
            quote!(-> BwStream<&Cipher>),
            quote!(-> BwStream<Self>),
            quote!(-> BwStream<HashMap<String, Cipher>>),
            quote!(-> BwStream<<T as Trait>::Item>),
            quote!(-> BwStream<Vec<Result<Cipher, Error>>>),
            quote!(-> Vec<BwStream<Cipher>>),
        ] {
            let err = infer(output.clone()).expect_err(&output.to_string());
            assert!(
                err.to_string().contains("cannot infer the TypeScript type"),
                "{err}"
            );
        }
    }
}
