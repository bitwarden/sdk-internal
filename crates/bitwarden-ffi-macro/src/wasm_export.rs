use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{
    Attribute, FnArg, ImplItem, ItemFn, ItemImpl, Meta, Pat, ReturnType, Signature, parse2,
    spanned::Spanned,
};

use crate::{
    attrs::{self, Args},
    wire::{crosses_bare, from_wire_type, split_result, to_wire_type},
};

/// What the shim needs beyond the function's own signature.
struct Shim {
    /// `wasm_bindgen(..)` arguments taken off the function, which travel with the shim.
    moved: Args,
    /// Whether the item sits in an impl block, so an associated function is called through
    /// `Self::`.
    in_impl: bool,
    /// The function's name before any `#[wasm_only]` rename, which is the JS-facing name.
    export_name: syn::Ident,
}

/// Builds the wasm shim for one method or free function.
fn build_shim(sig: &Signature, item_attrs: &[Attribute], shim: &Shim) -> syn::Result<TokenStream> {
    let Shim {
        moved,
        in_impl,
        export_name,
    } = shim;

    // The function as it stands now, which `#[wasm_only]` may already have renamed.
    let callee = &sig.ident;

    if !sig.generics.params.is_empty() {
        return Err(syn::Error::new(
            sig.generics.span(),
            "#[wasm_export] does not support generic methods; wasm_bindgen cannot export them",
        ));
    }

    // Rebuild the function's `#[wasm_bindgen(..)]`. A `constructor` is named by wasm_bindgen
    // itself, which rejects a `js_name` on one; every other shim needs one, because its Rust name
    // is mangled.
    let mut bindgen_args = moved.clone();
    let named = moved.iter().any(|meta| meta.path().is_ident("js_name"));
    let is_constructor = moved.iter().any(|meta| meta.path().is_ident("constructor"));
    if !named && !is_constructor {
        let name = export_name.to_string();
        bindgen_args.push(Meta::NameValue(syn::parse_quote!(js_name = #name)));
    }
    // Inside an impl block the enclosing `#[wasm_bindgen]` consumes this as one of its own helper
    // attributes, so it is never resolved as a path. On a free function there is no enclosing
    // block, which makes this the macro invocation itself and the path load-bearing.
    let forwarded = if *in_impl {
        quote!(#[wasm_bindgen(#bindgen_args)])
    } else {
        quote!(#[::bitwarden_ffi::_macro::wasm_bindgen(#bindgen_args)])
    };

    // Split the receiver from the parameters, projecting each parameter onto its wire type.
    let mut receiver: Option<TokenStream> = None;
    let mut params: Vec<TokenStream> = Vec::new();
    let mut conversions: Vec<TokenStream> = Vec::new();
    let mut call_args: Vec<TokenStream> = Vec::new();

    for (i, input) in sig.inputs.iter().enumerate() {
        match input {
            FnArg::Receiver(recv) => receiver = Some(recv.to_token_stream()),
            FnArg::Typed(pat_type) => {
                // Bind positionally: the original pattern may be `mut x` or a destructuring
                // pattern.
                let name = match &*pat_type.pat {
                    Pat::Ident(pat) => pat.ident.clone(),
                    _ => syn::Ident::new(&format!("__arg{i}"), pat_type.pat.span()),
                };
                let ty = &*pat_type.ty;

                if crosses_bare(ty) {
                    params.push(quote!(#name: #ty));
                } else {
                    let wire = from_wire_type(ty);
                    params.push(quote!(#name: #wire));
                    conversions.push(quote! {
                        let #name = <#ty as ::bitwarden_ffi::FromWasm>::from_wire(#name)
                            .map_err(::bitwarden_ffi::TsError::Conversion)?;
                    });
                }
                call_args.push(quote!(#name));
            }
        }
    }

    let is_async = sig.asyncness.is_some();
    let await_tok = is_async.then(|| quote!(.await));
    let async_tok = is_async.then(|| quote!(async));
    let call = match (&receiver, in_impl) {
        (Some(_), _) => quote!(self.#callee(#(#call_args),*)#await_tok),
        (None, true) => quote!(Self::#callee(#(#call_args),*)#await_tok),
        (None, false) => quote!(#callee(#(#call_args),*)#await_tok),
    };

    let ret_ty = match &sig.output {
        ReturnType::Default => None,
        ReturnType::Type(_, ty) => Some(&**ty),
    };
    let result_parts = ret_ty.and_then(split_result);
    // The value handed back to JavaScript: a `Result`'s `Ok` type, else the return type.
    let returned = result_parts.map(|(ok, _)| ok).or(ret_ty);
    let convert_return = returned.is_some_and(|ty| !crosses_bare(ty));

    let all_params: Vec<TokenStream> = receiver.iter().cloned().chain(params).collect();
    // The shim has to be configured out with the function it calls, or it would reference an item
    // that is not there.
    let carried = item_attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc") || attr.path().is_ident("cfg"));
    let shim_ident = syn::Ident::new(&format!("__wasm_ts_{export_name}"), export_name.span());

    // Every shim is fallible, including the ones where nothing can fail. wasm_bindgen renders
    // `Result<T, E>` as `T` plus a throw, so a caller cannot tell the difference.
    //
    // `TsError<E>` delegates to the function's own `From<E> for JsValue`, so a `bitwarden_error`
    // type keeps its existing `name` and `variant`. An infallible function leaves `E` defaulted.
    let error = match result_parts {
        Some((_, err_ty)) => quote!(::bitwarden_ffi::TsError<#err_ty>),
        None => quote!(::bitwarden_ffi::TsError),
    };
    let produce = match result_parts {
        Some(_) => quote!(#call.map_err(::bitwarden_ffi::TsError::Inner)?),
        None => call,
    };
    let (output, tail) = match returned.filter(|_| convert_return) {
        Some(ty) => (
            to_wire_type(ty),
            quote! {
                <#ty as ::bitwarden_ffi::ToWasm>::to_wire(__out)
                    .map_err(::bitwarden_ffi::TsError::Conversion)
            },
        ),
        // A reference or no return value at all, so it passes straight through.
        None => (
            returned.map_or_else(|| quote!(()), |ty| quote!(#ty)),
            quote!(::core::result::Result::Ok(__out)),
        ),
    };

    Ok(quote! {
        #(#carried)*
        #forwarded
        #[doc(hidden)]
        // A shim is a mechanical forwarder; the deprecation on what it calls is aimed at Rust
        // callers, and `#[wasm_only]` puts one there itself.
        #[allow(deprecated)]
        pub #async_tok fn #shim_ident(#(#all_params),*)
            -> ::core::result::Result<#output, #error>
        {
            #(#conversions)*
            let __out = #produce;
            #tail
        }
    })
}

/// Generates wire-converting `#[wasm_bindgen]` shims alongside the original item, which is left as
/// written for Rust and UniFFI consumers.
pub(crate) fn wasm_export(attr: TokenStream, item: TokenStream) -> TokenStream {
    match parse2::<ItemImpl>(item.clone()) {
        Ok(impl_block) => wasm_export_impl(attr, impl_block),
        // An impl block is by far the common case, so its parse error is the one worth reporting
        // when the item is neither.
        Err(impl_err) => match parse2::<ItemFn>(item) {
            Ok(function) => wasm_export_fn(attr, function),
            Err(_) => impl_err.to_compile_error(),
        },
    }
}

/// `#[wasm_export]` on an impl block: a second impl block of shims is generated beside it.
fn wasm_export_impl(attr: TokenStream, mut impl_block: ItemImpl) -> TokenStream {
    let forwarded = match attrs::parse_args(attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error(),
    };

    if let Err(err) = check_exportable(&impl_block.generics, &impl_block.attrs, "impl blocks") {
        return err.to_compile_error();
    }

    let self_ty = impl_block.self_ty.clone();
    let mut shims = Vec::new();

    for item in &mut impl_block.items {
        let ImplItem::Fn(method) = item else { continue };

        // Applied before the visibility check so the marker is never silently dropped: on a
        // private method it still renames and deprecates, it just produces no shim.
        let export_name = match apply_wasm_only(&mut method.attrs, &mut method.sig) {
            Ok(name) => name,
            Err(err) => return err.to_compile_error(),
        };

        // Match wasm_bindgen's own rule: every `pub` method in the block is exported. Shimming
        // only the methods that convert something would silently unexport the rest, since this
        // block no longer carries `#[wasm_bindgen]`.
        if !matches!(method.vis, syn::Visibility::Public(_)) {
            continue;
        }

        match take_shim(
            &mut method.attrs,
            &method.sig,
            true,
            export_name,
            Args::new(),
        ) {
            Ok(shim) => shims.push(shim),
            Err(err) => return err.to_compile_error(),
        }
    }

    if shims.is_empty() {
        return impl_block.into_token_stream();
    }

    let bindgen_args = (!forwarded.is_empty()).then(|| quote!((#forwarded)));
    // As for a method: the shims have to be configured out with the block they call into.
    let cfgs = impl_block
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg"))
        .cloned()
        .collect::<Vec<_>>();

    quote! {
        #impl_block

        #(#cfgs)*
        #[cfg(feature = "wasm")]
        #[::bitwarden_ffi::_macro::wasm_bindgen #bindgen_args]
        impl #self_ty {
            #(#shims)*
        }
    }
}

/// `#[wasm_export]` on a free function: the original is untouched, and a sibling shim is generated.
fn wasm_export_fn(attr: TokenStream, mut function: ItemFn) -> TokenStream {
    let forwarded = match attrs::parse_args(attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error(),
    };

    if let Err(err) = check_exportable(&function.sig.generics, &function.attrs, "functions") {
        return err.to_compile_error();
    }

    let export_name = match apply_wasm_only(&mut function.attrs, &mut function.sig) {
        Ok(name) => name,
        Err(err) => return err.to_compile_error(),
    };

    if !matches!(function.vis, syn::Visibility::Public(_)) {
        return function.into_token_stream();
    }

    // There is no generated block to carry this macro's own arguments, so they join the shim's.
    let shim = match take_shim(
        &mut function.attrs,
        &function.sig,
        false,
        export_name,
        forwarded,
    ) {
        Ok(shim) => shim,
        Err(err) => return err.to_compile_error(),
    };

    quote! {
        #function

        #[cfg(feature = "wasm")]
        #shim
    }
}

/// Builds one function's shim, moving the `#[wasm_bindgen(..)]` it declares onto that shim.
///
/// `moved` is prepended to the arguments the shim carries.
fn take_shim(
    item_attrs: &mut Vec<Attribute>,
    sig: &Signature,
    in_impl: bool,
    export_name: syn::Ident,
    mut moved: Args,
) -> syn::Result<TokenStream> {
    // The original block is no longer `#[wasm_bindgen]`, so these cannot stay behind.
    item_attrs.retain(|attr| match attrs::wasm_bindgen_args(attr) {
        Some(args) => {
            moved.extend(args);
            false
        }
        None => true,
    });

    build_shim(
        sig,
        item_attrs,
        &Shim {
            moved,
            in_impl,
            export_name,
        },
    )
}

/// Rejects a generic item, which wasm_bindgen cannot export, and a leftover `#[wasm_bindgen]`.
///
/// `kind` names the item in the error, plural, as in "generic impl blocks".
fn check_exportable(
    generics: &syn::Generics,
    item_attrs: &[Attribute],
    kind: &str,
) -> syn::Result<()> {
    if !generics.params.is_empty() {
        return Err(syn::Error::new(
            generics.span(),
            format!(
                "#[wasm_export] does not support generic {kind}; wasm_bindgen cannot export them"
            ),
        ));
    }

    if let Some(attr) = attrs::find_wasm_bindgen(item_attrs) {
        return Err(syn::Error::new_spanned(
            attr,
            "#[wasm_export] replaces #[wasm_bindgen]; pass its arguments to #[wasm_export] \
             instead, as in #[wasm_export(js_class = Foo)]",
        ));
    }

    Ok(())
}

/// Applies `#[wasm_only]`, if present, returning the JS-facing name.
///
/// The marker means JavaScript is the only intended caller. Rename the function so Rust callers do
/// not reach for it, hide it from documentation, and deprecate it so any that do get a warning and
/// see it struck through in autocomplete. The JS name is unaffected: it lives on the shim, which
/// calls the renamed function.
fn apply_wasm_only(attrs: &mut Vec<Attribute>, sig: &mut Signature) -> syn::Result<syn::Ident> {
    let export_name = sig.ident.clone();
    let idx = attrs.iter().position(|a| a.path().is_ident("wasm_only"));
    let Some(idx) = idx else {
        return Ok(export_name);
    };
    let note = wasm_only_note(&attrs.remove(idx))?;

    attrs.push(syn::parse_quote!(#[doc(hidden)]));
    attrs.push(syn::parse_quote!(#[deprecated(note = #note)]));
    attrs.push(syn::parse_quote!(#[allow(deprecated)]));
    sig.ident = syn::Ident::new(&format!("__wasm_only_{export_name}"), sig.ident.span());

    Ok(export_name)
}

/// Reads the deprecation note from `#[wasm_only]` / `#[wasm_only(note = "...")]`.
fn wasm_only_note(attr: &Attribute) -> syn::Result<String> {
    const DEFAULT: &str = "This is a WASM-only binding. Calling it from Rust is not allowed.";
    if attr.meta.require_path_only().is_ok() {
        return Ok(DEFAULT.to_owned());
    }

    let mut note = None;
    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("note") {
            note = Some(meta.value()?.parse::<syn::LitStr>()?.value());
            Ok(())
        } else {
            Err(meta.error("unknown attribute, expected `note`"))
        }
    })?;
    Ok(note.unwrap_or_else(|| DEFAULT.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expansion with the whitespace `TokenStream::to_string` inserts between tokens removed, so
    /// assertions can be written the way the code is.
    fn expand(attr: TokenStream, item: TokenStream) -> String {
        wasm_export(attr, item).to_string().replace(' ', "")
    }

    #[test]
    fn leaves_the_original_block_as_written_and_generates_a_shim_block() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    pub fn translate(&self, point: Point) -> Point { point }
                }
            },
        );

        assert!(!out.contains("compile_error!"), "{out}");
        // The method keeps its plain Rust signature for Rust and UniFFI callers.
        assert!(
            out.contains("pubfntranslate(&self,point:Point)->Point{point}"),
            "{out}"
        );
        assert!(
            out.contains("#[::bitwarden_ffi::_macro::wasm_bindgen]implCanvas{"),
            "{out}"
        );
        assert!(out.contains("fn__wasm_ts_translate"), "{out}");
    }

    #[test]
    fn projects_parameters_and_returns_onto_their_wire_types() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    pub fn translate(&self, point: Point) -> Result<Point, MoveError> { Ok(point) }
                }
            },
        );

        assert!(out.contains("js_name=\"translate\""), "{out}");
        assert!(
            out.contains("<Pointas::bitwarden_ffi::FromWasm>::Wire"),
            "{out}"
        );
        assert!(
            out.contains("<Pointas::bitwarden_ffi::ToWasm>::Wire"),
            "{out}"
        );
        assert!(out.contains("::bitwarden_ffi::TsError<MoveError>"), "{out}");
    }

    #[test]
    fn projects_a_handle_type_the_same_way() {
        // `CiphersClient`'s own `#[wasm_object]` makes `Wire = Self`, so a handle needs no special
        // case here.
        let out = expand(
            TokenStream::new(),
            quote! {
                impl VaultClient {
                    pub fn ciphers(&self) -> CiphersClient { todo!() }
                }
            },
        );

        assert!(
            out.contains("<CiphersClientas::bitwarden_ffi::ToWasm>::Wire"),
            "{out}"
        );
    }

    #[test]
    fn projects_the_impls_own_type_like_any_other() {
        // The self type is always a handle, so this projection is a no-op — but it is not special
        // cased, so a constructor's shim is fallible with an unreachable `Err`. The `.d.ts` is the
        // same either way, since wasm_bindgen renders `Result<T, E>` as `T` plus a throw.
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    pub fn new() -> Self { Canvas }
                }
            },
        );

        assert!(
            out.contains("<Selfas::bitwarden_ffi::ToWasm>::Wire"),
            "{out}"
        );
    }

    #[test]
    fn defaults_the_error_for_an_infallible_method() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    pub fn width(&self) -> u32 { 0 }
                }
            },
        );

        assert!(out.contains("::bitwarden_ffi::TsError>"), "{out}");
        assert!(!out.contains("TsError<"), "{out}");
    }

    #[test]
    fn leaves_reference_parameters_alone() {
        // `Ts<T>` is passed by value, so a reference can never be wrapped.
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    pub fn draw(&self, backend: &JsBackend) -> u32 { 0 }
                }
            },
        );

        assert!(out.contains("backend:&JsBackend"), "{out}");
        assert!(!out.contains("<&JsBackendas"), "{out}");
    }

    #[test]
    fn awaits_an_async_method() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    pub async fn save(&self, point: Point) -> Point { point }
                }
            },
        );

        assert!(out.contains("pubasyncfn__wasm_ts_save"), "{out}");
        assert!(out.contains("self.save(point).await"), "{out}");
    }

    #[test]
    fn calls_an_associated_function_through_self() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    pub fn blank(width: u32) -> Canvas { todo!() }
                }
            },
        );

        assert!(out.contains("Self::blank(width)"), "{out}");
    }

    #[test]
    fn forwards_its_arguments_to_the_generated_block() {
        let out = expand(
            quote!(js_class = IpcClient),
            quote! {
                impl JsIpcClient {
                    pub fn is_running(&self) -> bool { true }
                }
            },
        );

        assert!(
            out.contains("#[::bitwarden_ffi::_macro::wasm_bindgen(js_class=IpcClient)]"),
            "{out}"
        );
    }

    #[test]
    fn moves_a_method_attribute_onto_its_shim() {
        // The original block is no longer `#[wasm_bindgen]`, so the attribute cannot stay behind.
        let out = expand(
            TokenStream::new(),
            quote! {
                impl PolicyClient {
                    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "get_enforced"))]
                    pub fn get_enforced(&self) {}
                }
            },
        );

        assert_eq!(out.matches("js_name=").count(), 1, "{out}");
        assert!(out.contains("js_name=\"get_enforced\""), "{out}");
        assert!(
            !out.contains("cfg_attr(feature=\"wasm\",wasm_bindgen"),
            "{out}"
        );
    }

    #[test]
    fn leaves_a_constructor_for_wasm_bindgen_to_name() {
        // wasm_bindgen names a constructor itself and rejects a `js_name` on one.
        let out = expand(
            TokenStream::new(),
            quote! {
                impl JsIpcClient {
                    #[wasm_bindgen(constructor)]
                    pub fn new() -> JsIpcClient { todo!() }
                }
            },
        );

        assert!(!out.contains("js_name"), "{out}");
        assert!(out.contains("fn__wasm_ts_new"), "{out}");
    }

    #[test]
    fn carries_a_cfg_from_the_impl_block_onto_the_shim_block() {
        // The shims call into the block, so they have to be configured out with it.
        let out = expand(
            TokenStream::new(),
            quote! {
                #[cfg(target_arch = "wasm32")]
                impl Canvas {
                    pub fn translate(&self, point: Point) -> Point { point }
                }
            },
        );

        assert_eq!(
            out.matches("#[cfg(target_arch=\"wasm32\")]").count(),
            2,
            "{out}"
        );
    }

    #[test]
    fn carries_a_cfg_and_docs_from_a_method_onto_its_shim() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    /// Translates the point.
                    #[cfg(feature = "geometry")]
                    pub fn translate(&self, point: Point) -> Point { point }
                }
            },
        );

        assert_eq!(
            out.matches("#[cfg(feature=\"geometry\")]").count(),
            2,
            "{out}"
        );
        assert_eq!(out.matches("Translatesthepoint.").count(), 2, "{out}");
    }

    #[test]
    fn renames_a_wasm_only_method_and_keeps_its_js_name_on_the_shim() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl JsIpcClient {
                    #[wasm_only]
                    pub fn is_running(&self) -> bool { true }
                }
            },
        );

        assert!(out.contains("fn__wasm_only_is_running"), "{out}");
        assert!(out.contains("self.__wasm_only_is_running()"), "{out}");
        assert!(out.contains("js_name=\"is_running\""), "{out}");
        assert!(out.contains("#[doc(hidden)]"), "{out}");
        assert!(
            out.contains(
                "#[deprecated(note=\"ThisisaWASM-onlybinding.CallingitfromRustisnotallowed.\")]"
            ),
            "{out}"
        );
    }

    #[test]
    fn carries_a_custom_note() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl JsIpcClient {
                    #[wasm_only(note = "Use `IpcClient::start`.")]
                    pub fn start(&self) {}
                }
            },
        );

        assert!(
            out.contains("#[deprecated(note=\"Use`IpcClient::start`.\")]"),
            "{out}"
        );
    }

    #[test]
    fn renames_a_private_wasm_only_method_without_shimming_it() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl JsIpcClient {
                    #[wasm_only]
                    fn internal(&self) {}
                }
            },
        );

        assert!(out.contains("fn__wasm_only_internal"), "{out}");
        assert!(!out.contains("__wasm_ts_"), "{out}");
    }

    #[test]
    fn leaves_a_private_generic_method_alone() {
        // wasm_bindgen only exports `pub` methods, so a private helper may stay generic.
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    pub fn width(&self) -> u32 { 0 }
                    fn draw<T: Shape>(&self, shape: T) {}
                }
            },
        );

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(!out.contains("__wasm_ts_draw"), "{out}");
    }

    #[test]
    fn generates_no_block_when_nothing_is_public() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    fn internal(&self) {}
                }
            },
        );

        assert!(!out.contains("wasm_bindgen"), "{out}");
    }

    #[test]
    fn rejects_a_generic_impl_block() {
        // `self_ty` already carries the parameters, so a second block would emit
        // `impl Canvas<T><T>`.
        let out = expand(
            TokenStream::new(),
            quote! {
                impl<T> Canvas<T> {
                    pub fn translate(&self, point: Point) -> Point { point }
                }
            },
        );

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("doesnotsupportgenericimplblocks"), "{out}");
    }

    #[test]
    fn rejects_a_generic_method() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    pub fn draw<T: Shape>(&self, shape: T) {}
                }
            },
        );

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("doesnotsupportgenericmethods"), "{out}");
    }

    #[test]
    fn rejects_a_block_that_still_carries_wasm_bindgen() {
        // The macro stands in for the attribute rather than decorating it, so leaving one behind
        // would export every method twice.
        let out = expand(
            TokenStream::new(),
            quote! {
                #[wasm_bindgen(js_class = IpcClient)]
                impl JsIpcClient {
                    pub fn is_running(&self) -> bool { true }
                }
            },
        );

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("replaces#[wasm_bindgen]"), "{out}");
    }

    #[test]
    fn shims_a_free_function() {
        // There is no generated block, so the shim carries the attribute itself and this macro's
        // arguments join its.
        let out = expand(
            quote!(js_name = doThing),
            quote! {
                pub fn do_thing(point: Point) -> Point { point }
            },
        );

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(out.contains("pubfndo_thing(point:Point)->Point"), "{out}");
        assert!(
            out.contains("#[::bitwarden_ffi::_macro::wasm_bindgen(js_name=doThing)]"),
            "{out}"
        );
        assert!(out.contains("fn__wasm_ts_do_thing"), "{out}");
        assert!(out.contains("do_thing(point)"), "{out}");
    }

    #[test]
    fn leaves_a_private_free_function_unshimmed() {
        let out = expand(
            TokenStream::new(),
            quote! {
                fn do_thing(point: Point) -> Point { point }
            },
        );

        assert!(!out.contains("__wasm_ts_"), "{out}");
    }

    #[test]
    fn rejects_a_generic_free_function() {
        let out = expand(
            TokenStream::new(),
            quote! {
                pub fn do_thing<T>(value: T) {}
            },
        );

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("doesnotsupportgenericfunctions"), "{out}");
    }

    #[test]
    fn rejects_an_item_that_is_neither() {
        let out = expand(TokenStream::new(), quote! { pub struct Canvas; });

        assert!(out.contains("compile_error!"), "{out}");
    }
}
