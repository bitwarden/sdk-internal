use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{
    Attribute, FnArg, GenericArgument, ImplItem, ItemFn, ItemImpl, PathArguments, Signature, Type,
};

use crate::attrs;

/// The list parameter type that crosses from JavaScript as an array of its items.
const LARGE_VEC: &str = "LargeVec";

/// Rust primitives and `String`, which a `LARGE_VEC` cannot be typed from by name.
const PRIMITIVES: &[&str] = &[
    "String", "str", "char", "bool", "u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64", "u128",
    "i128", "usize", "isize", "f32", "f64",
];

/// Emits an impl block under `bindgen`, its `#[wasm_bindgen]`, or twice when a method has a
/// parameter attribute: with `bindgen` and plain parameter attributes under the `wasm` feature, and
/// without either otherwise.
///
/// rustc does not expand a `cfg_attr` on a parameter before the impl block's `#[wasm_bindgen]`
/// reads it, and a plain one is an unknown attribute without the `wasm` feature, so no single
/// spelling works in both builds. Only one copy exists per build, so documentation shows one.
pub(crate) fn per_feature_impl(bindgen: TokenStream, mut impl_block: ItemImpl) -> TokenStream {
    let has_wasm_attrs = impl_block
        .items
        .iter()
        .any(|item| matches!(item, ImplItem::Fn(method) if has_wasm_attrs(&method.sig)));
    if !has_wasm_attrs {
        return quote! {
            #bindgen
            #impl_block
        };
    }

    let mut native = impl_block.clone();
    for (wasm, native) in impl_block.items.iter_mut().zip(&mut native.items) {
        if let (ImplItem::Fn(wasm), ImplItem::Fn(native)) = (wasm, native) {
            for_wasm(&mut wasm.sig);
            for_native(&mut native.sig);
        }
    }
    quote! {
        #[cfg(feature = "wasm")]
        #bindgen
        #impl_block

        #[cfg(not(feature = "wasm"))]
        #native
    }
}

/// [`per_feature_impl`] for a free function.
pub(crate) fn per_feature_fn(bindgen: TokenStream, mut function: ItemFn) -> TokenStream {
    if !has_wasm_attrs(&function.sig) {
        return quote! {
            #bindgen
            #function
        };
    }

    let mut native = function.clone();
    for_wasm(&mut function.sig);
    for_native(&mut native.sig);
    quote! {
        #[cfg(feature = "wasm")]
        #bindgen
        #function

        #[cfg(not(feature = "wasm"))]
        #native
    }
}

/// Declares the TypeScript type of each `LargeVec<T>` parameter as `T[]`, unless the parameter
/// declares one itself. wasm_bindgen types it as `any`, because the item type is generic.
///
/// The type is declared with a plain `#[wasm_bindgen(..)]`, which [`per_feature_impl`] handles
/// like any other parameter attribute.
pub(crate) fn infer_param_types(sig: &mut Signature) -> syn::Result<()> {
    for input in &mut sig.inputs {
        let FnArg::Typed(param) = input else { continue };
        let Some(item) = large_vec_item(&param.ty) else {
            continue;
        };

        let declares_type = param
            .attrs
            .iter()
            .filter_map(attrs::wasm_bindgen_args)
            .flatten()
            .any(|meta| {
                meta.path().is_ident("unchecked_param_type")
                    || meta.path().is_ident("unchecked_optional_param_type")
            });
        if declares_type {
            continue;
        }

        let ts = format!("{}[]", item_name(item, &param.ty)?);
        param
            .attrs
            .push(syn::parse_quote!(#[wasm_bindgen(unchecked_param_type = #ts)]));
    }
    Ok(())
}

/// Whether any parameter carries a `#[wasm_bindgen(..)]`, written plainly or under
/// `#[cfg_attr(feature = "wasm", ..)]`.
fn has_wasm_attrs(sig: &Signature) -> bool {
    params(sig).any(|param_attrs| param_attrs.iter().any(is_wasm_attr))
}

/// Writes every parameter's `#[wasm_bindgen(..)]` plainly, the only form wasm_bindgen reads.
fn for_wasm(sig: &mut Signature) {
    for param_attrs in params_mut(sig) {
        for attr in param_attrs.iter_mut() {
            if let Some(args) = attrs::wasm_bindgen_args(attr) {
                *attr = syn::parse_quote!(#[wasm_bindgen(#args)]);
            }
        }
    }
}

/// Removes every parameter's `#[wasm_bindgen(..)]`, which nothing reads without the `wasm`
/// feature.
fn for_native(sig: &mut Signature) {
    for param_attrs in params_mut(sig) {
        param_attrs.retain(|attr| !is_wasm_attr(attr));
    }
}

fn is_wasm_attr(attr: &Attribute) -> bool {
    attrs::wasm_bindgen_args(attr).is_some()
}

fn params(sig: &Signature) -> impl Iterator<Item = &Vec<Attribute>> {
    sig.inputs.iter().filter_map(|input| match input {
        FnArg::Typed(param) => Some(&param.attrs),
        FnArg::Receiver(_) => None,
    })
}

fn params_mut(sig: &mut Signature) -> impl Iterator<Item = &mut Vec<Attribute>> {
    sig.inputs.iter_mut().filter_map(|input| match input {
        FnArg::Typed(param) => Some(&mut param.attrs),
        FnArg::Receiver(_) => None,
    })
}

/// The item type of a `LargeVec<T>`.
fn large_vec_item(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else { return None };
    let segment = path.path.segments.last()?;
    if path.qself.is_some() || segment.ident != LARGE_VEC {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    match arguments.args.iter().collect::<Vec<_>>().as_slice() {
        [GenericArgument::Type(item)] => Some(item),
        _ => None,
    }
}

/// The TypeScript name of a list item: the last segment of its path, which is the name of a
/// `#[wasm_record]` type unless it is renamed for JavaScript.
fn item_name(item: &Type, list: &Type) -> syn::Result<String> {
    if let Type::Path(path) = item
        && path.qself.is_none()
        && let Some(segment) = path.path.segments.last()
        && segment.arguments.is_none()
        && segment.ident != "Self"
        && !PRIMITIVES
            .iter()
            .any(|primitive| segment.ident == primitive)
    {
        return Ok(segment.ident.to_string());
    }

    Err(syn::Error::new_spanned(
        list,
        format!(
            "#[wasm_export] cannot infer the TypeScript type of `{}`; declare it with \
             #[wasm_bindgen(unchecked_param_type = \"...\")]",
            list.to_token_stream()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use quote::quote;

    use super::*;

    /// The `#[wasm_export]` expansion with whitespace removed, as in its own tests.
    fn expand(attr: TokenStream, item: TokenStream) -> String {
        crate::wasm_export::wasm_export(attr, item)
            .to_string()
            .replace(' ', "")
    }

    /// The copy for the `wasm` feature and the copy for without it, each without its `cfg`.
    fn split(out: &str) -> (&str, &str) {
        let (before, wasm) = out
            .split_once("#[cfg(feature=\"wasm\")]")
            .unwrap_or_else(|| panic!("no wasm copy: {out}"));
        let (wasm, native) = wasm
            .split_once("#[cfg(not(feature=\"wasm\"))]")
            .unwrap_or_else(|| panic!("no native copy: {out}"));
        assert!(before.is_empty(), "{out}");
        (wasm, native)
    }

    #[test]
    fn emits_a_block_without_parameter_attributes_once() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl CiphersClient {
                    pub fn import(&self, ciphers: Vec<Cipher>) {}
                }
            },
        );

        assert!(!out.contains("#[cfg("), "{out}");
        assert_eq!(out.matches("fnimport").count(), 1, "{out}");
        assert!(
            out.starts_with("#[cfg_attr(feature=\"wasm\",::bitwarden_ffi::_macro::wasm_bindgen)]"),
            "{out}"
        );
    }

    #[test]
    fn keeps_a_plain_parameter_attribute_only_for_wasm() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl CiphersClient {
                    pub fn import(
                        &self,
                        #[wasm_bindgen(unchecked_param_type = "Cipher[]")] ciphers: Vec<JsValue>,
                    ) {}
                }
            },
        );

        let (wasm, native) = split(&out);
        assert!(
            wasm.contains("::bitwarden_ffi::_macro::wasm_bindgen)]"),
            "{out}"
        );
        assert!(
            wasm.contains("#[wasm_bindgen(unchecked_param_type=\"Cipher[]\")]ciphers:Vec<JsValue>"),
            "{out}"
        );
        assert!(!native.contains("wasm_bindgen"), "{out}");
        assert!(
            native.contains("pubfnimport(&self,ciphers:Vec<JsValue>,)"),
            "{out}"
        );
    }

    #[test]
    fn writes_a_cfg_attr_parameter_attribute_plainly_for_wasm() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl CiphersClient {
                    pub fn import(
                        &self,
                        #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = cipherList))]
                        ciphers: Vec<Cipher>,
                    ) {}
                }
            },
        );

        let (wasm, native) = split(&out);
        assert!(
            wasm.contains("#[wasm_bindgen(js_name=cipherList)]ciphers:Vec<Cipher>"),
            "{out}"
        );
        assert!(
            !out.contains("cfg_attr(feature=\"wasm\",wasm_bindgen"),
            "{out}"
        );
        assert!(!native.contains("cipherList"), "{out}");
    }

    #[test]
    fn declares_the_type_of_a_large_vec_parameter() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl CiphersClient {
                    pub fn import(&self, ciphers: LargeVec<crate::Cipher>) {}
                }
            },
        );

        let (wasm, native) = split(&out);
        assert!(
            wasm.contains(
                "#[wasm_bindgen(unchecked_param_type=\"Cipher[]\")]ciphers:LargeVec<crate::Cipher>"
            ),
            "{out}"
        );
        assert!(
            native.contains("(&self,ciphers:LargeVec<crate::Cipher>)"),
            "{out}"
        );
    }

    #[test]
    fn keeps_a_type_a_large_vec_parameter_declares() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl CiphersClient {
                    pub fn import(
                        &self,
                        #[wasm_bindgen(unchecked_param_type = "CipherRecord[]")]
                        ciphers: LargeVec<Cipher>,
                    ) {}
                }
            },
        );

        assert_eq!(out.matches("unchecked_param_type").count(), 1, "{out}");
        assert!(out.contains("CipherRecord[]"), "{out}");
    }

    #[test]
    fn leaves_a_private_large_vec_parameter_alone() {
        // wasm_bindgen does not export the method, so its parameter types do not matter.
        let out = expand(
            TokenStream::new(),
            quote! {
                impl CiphersClient {
                    fn import(&self, ciphers: LargeVec<Cipher>) {}
                }
            },
        );

        assert!(!out.contains("#[cfg("), "{out}");
        assert!(!out.contains("unchecked_param_type"), "{out}");
    }

    #[test]
    fn rejects_a_large_vec_of_a_type_it_cannot_name() {
        for item in [
            quote!(String),
            quote!(Vec<Cipher>),
            quote!(Self),
            quote!((u8, u8)),
        ] {
            let out = expand(
                TokenStream::new(),
                quote! {
                    impl CiphersClient {
                        pub fn import(&self, ciphers: LargeVec<#item>) {}
                    }
                },
            );

            assert!(out.contains("compile_error!"), "{out}");
            assert!(out.contains("cannotinfertheTypeScripttype"), "{out}");
        }
    }

    #[test]
    fn renames_a_wasm_only_method_in_both_copies() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl CiphersClient {
                    #[wasm_only]
                    pub fn import(&self, ciphers: LargeVec<Cipher>) {}
                }
            },
        );

        let (wasm, native) = split(&out);
        for copy in [wasm, native] {
            assert!(copy.contains("pubfn__wasm_only_import"), "{out}");
            assert!(copy.contains("#[deprecated("), "{out}");
            assert!(
                copy.contains("#[cfg_attr(feature=\"wasm\",wasm_bindgen(js_name=\"import\"))]"),
                "{out}"
            );
        }
        assert!(wasm.contains("unchecked_param_type=\"Cipher[]\""), "{out}");
        assert!(!native.contains("unchecked_param_type"), "{out}");
    }

    #[test]
    fn emits_a_free_function_with_parameter_attributes_per_feature() {
        let out = expand(
            quote!(js_name = importCiphers),
            quote! {
                pub fn import_ciphers(ciphers: LargeVec<Cipher>) {}
            },
        );

        let (wasm, native) = split(&out);
        assert!(
            wasm.contains("::bitwarden_ffi::_macro::wasm_bindgen(js_name=importCiphers))]"),
            "{out}"
        );
        assert!(
            wasm.contains("#[wasm_bindgen(unchecked_param_type=\"Cipher[]\")]ciphers"),
            "{out}"
        );
        assert!(!native.contains("wasm_bindgen"), "{out}");
        assert!(
            native.contains("pubfnimport_ciphers(ciphers:LargeVec<Cipher>)"),
            "{out}"
        );
    }

    #[test]
    fn emits_a_free_function_without_parameter_attributes_once() {
        let out = expand(
            TokenStream::new(),
            quote! {
                pub fn import_ciphers(ciphers: Vec<Cipher>) {}
            },
        );

        assert!(!out.contains("#[cfg("), "{out}");
        assert_eq!(out.matches("fnimport_ciphers").count(), 1, "{out}");
    }
}
