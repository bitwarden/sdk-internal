use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{
    Attribute, FnArg, ImplItem, ItemFn, ItemImpl, Meta, Pat, ReturnType, Signature, Token, Type,
    parse::Parser, parse2, punctuated::Punctuated, spanned::Spanned,
};

/// The type JavaScript passes for a parameter of type `ty`.
///
/// `#[wasm_record]` and `#[wasm_object]` implement `FromWasm` at each type's declaration site, so
/// this resolves to `Ts<T>` for a serde DTO and to `T` for a `#[wasm_bindgen]` handle. A type that
/// has declared neither is a missing-impl error naming the site.
fn from_wire_type(ty: &Type) -> TokenStream {
    quote!(<#ty as ::bitwarden_ffi::FromWasm>::Wire)
}

/// The type JavaScript receives for a return of type `ty`.
fn to_wire_type(ty: &Type) -> TokenStream {
    quote!(<#ty as ::bitwarden_ffi::ToWasm>::Wire)
}

/// Whether a value crosses the ABI as written, with no wire conversion.
///
/// References only: `Ts<T>` is passed by value, so a reference can never be wrapped. Covers `&[u8]`
/// and borrowed handles such as `&JsCommunicationBackend`.
fn crosses_bare(ty: &Type) -> bool {
    matches!(ty, Type::Reference(_))
}

/// `Result<R, E>` -> `(R, E)`.
fn split_result(ty: &Type) -> Option<(&Type, &Type)> {
    let Type::Path(p) = ty else { return None };
    let seg = p.path.segments.last()?;
    if seg.ident != "Result" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    let mut it = args.args.iter().filter_map(|a| match a {
        syn::GenericArgument::Type(t) => Some(t),
        _ => None,
    });
    Some((it.next()?, it.next()?))
}

/// Pulls the `wasm_bindgen(..)` arguments off an attribute so they can be reattached to the shim.
///
/// Handles both `#[wasm_bindgen(..)]` and `#[cfg_attr(feature = "wasm", wasm_bindgen(..))]`. The
/// original block is not `#[wasm_bindgen]`, so leaving either in place would not compile.
fn wasm_bindgen_args(attr: &Attribute) -> Option<Punctuated<Meta, Token![,]>> {
    let inner = if attr.path().is_ident("wasm_bindgen") {
        attr.meta.clone()
    } else if attr.path().is_ident("cfg_attr") {
        let Meta::List(list) = &attr.meta else {
            return None;
        };
        list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .ok()?
            .into_iter()
            .find(|m| m.path().is_ident("wasm_bindgen"))?
    } else {
        return None;
    };

    Some(match inner {
        Meta::List(list) => list
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .ok()?,
        _ => Punctuated::new(),
    })
}

fn take_attr(attrs: &mut Vec<Attribute>, name: &str) -> Option<Attribute> {
    let idx = attrs.iter().position(|a| a.path().is_ident(name))?;
    Some(attrs.remove(idx))
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
            Err(meta.error("unknown argument, expected `note`"))
        }
    })?;
    Ok(note.unwrap_or_else(|| DEFAULT.to_owned()))
}

/// What the shim needs beyond the method's own signature.
struct Shim {
    /// `wasm_bindgen(..)` arguments taken off the method, which travel with the shim.
    moved: Punctuated<Meta, Token![,]>,
    /// Whether the item sits in an impl block, so an associated function is called through
    /// `Self::`.
    in_impl: bool,
    /// The method's name before any `#[wasm_only]` rename, which is the JS-facing name.
    export_name: syn::Ident,
}

/// Builds the wasm shim for one method or free function.
fn build_shim(sig: &Signature, attrs: &[Attribute], shim_ctx: &Shim) -> syn::Result<TokenStream> {
    let Shim {
        moved,
        in_impl,
        export_name,
    } = shim_ctx;

    // The function as it stands now, which `#[wasm_only]` may already have renamed.
    let callee = &sig.ident;

    if !sig.generics.params.is_empty() {
        return Err(syn::Error::new(
            sig.generics.span(),
            "#[wasm_export] does not support generic methods; wasm_bindgen cannot export them",
        ));
    }

    // Rebuild the method's `#[wasm_bindgen(..)]`. A `constructor` is named by wasm_bindgen itself,
    // so giving one a `js_name` is rejected; every other shim needs one, because its Rust name is
    // mangled.
    let mut bindgen_args = moved.clone();
    let named = moved.iter().any(|m| m.path().is_ident("js_name"));
    let is_constructor = moved.iter().any(|m| m.path().is_ident("constructor"));
    if !named && !is_constructor {
        let name = export_name.to_string();
        bindgen_args.push(Meta::NameValue(syn::parse_quote!(js_name = #name)));
    }
    let forwarded = quote!(#[wasm_bindgen(#bindgen_args)]);

    // Split the receiver from the parameters, projecting each parameter onto its wire type.
    let mut receiver: Option<TokenStream> = None;
    let mut params: Vec<TokenStream> = Vec::new();
    let mut conversions: Vec<TokenStream> = Vec::new();
    let mut call_args: Vec<TokenStream> = Vec::new();

    for (i, input) in sig.inputs.iter().enumerate() {
        match input {
            FnArg::Receiver(r) => receiver = Some(r.to_token_stream()),
            FnArg::Typed(pat_type) => {
                // Bind positionally: the original pattern may be `mut x` or a destructuring
                // pattern.
                let name = match &*pat_type.pat {
                    Pat::Ident(id) => id.ident.clone(),
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
        ReturnType::Type(_, t) => Some(&**t),
    };
    let result_parts = ret_ty.and_then(split_result);
    // The value handed back to JavaScript: a `Result`'s `Ok` type, else the return type.
    let returned = result_parts.map(|(ok, _)| ok).or(ret_ty);
    let convert_return = returned.is_some_and(|ty| !crosses_bare(ty));

    // A shim is a mechanical forwarder; the deprecation on what it calls is aimed at callers, and
    // `#[wasm_only]` puts one there itself.
    let allow_deprecated = quote!(#[allow(deprecated)]);
    let all_params: Vec<TokenStream> = receiver.iter().cloned().chain(params).collect();
    // The shim has to be configured out with the method it calls, or it would reference an item
    // that is not there.
    let carried = attrs
        .iter()
        .filter(|a| a.path().is_ident("doc") || a.path().is_ident("cfg"));
    let shim = syn::Ident::new(&format!("__wasm_ts_{export_name}"), export_name.span());

    // Every shim is fallible, including the ones where nothing can fail. wasm_bindgen renders
    // `Result<T, E>` as `T` plus a throw, so a caller cannot tell the difference.

    // `TsError<E>` delegates to the method's own `From<E> for JsValue`, so a `bitwarden_error` type
    // keeps its existing `name` and `variant`. An infallible method leaves `E` defaulted.
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
        #allow_deprecated
        pub #async_tok fn #shim(#(#all_params),*)
            -> ::core::result::Result<#output, #error>
        {
            #(#conversions)*
            let __out = #produce;
            #tail
        }
    })
}

/// Applies `#[wasm_only]`, if present, returning the JS-facing name.
///
/// The marker means JavaScript is the only intended caller. Rename the function so Rust callers do
/// not reach for it, and deprecate it so any that do get a warning. The JS name is unaffected: it
/// lives on the shim, which calls the renamed function.
fn apply_wasm_only(attrs: &mut Vec<Attribute>, sig: &mut Signature) -> syn::Result<syn::Ident> {
    let export_name = sig.ident.clone();
    let Some(marker) = take_attr(attrs, "wasm_only") else {
        return Ok(export_name);
    };
    let note = wasm_only_note(&marker)?;
    sig.ident = syn::Ident::new(&format!("__wasm_only_{export_name}"), sig.ident.span());
    attrs.push(syn::parse_quote!(#[doc(hidden)]));
    attrs.push(syn::parse_quote!(#[deprecated(note = #note)]));
    attrs.push(syn::parse_quote!(#[allow(deprecated)]));
    Ok(export_name)
}

/// Builds one function's shim, stripping the markers the compiler must not see.
///
/// `extra` is prepended to the `#[wasm_bindgen(..)]` the shim carries; for a free function that is
/// where this macro's own arguments go, since there is no generated block to put them on.
fn take_shim(
    attrs: &mut Vec<Attribute>,
    sig: &mut Signature,
    in_impl: bool,
    export_name: syn::Ident,
    mut moved: Punctuated<Meta, Token![,]>,
) -> syn::Result<TokenStream> {
    // The function's own wasm_bindgen attributes move onto the shim; they cannot stay behind.
    attrs.retain(|attr| match wasm_bindgen_args(attr) {
        Some(inner) => {
            moved.extend(inner);
            false
        }
        None => true,
    });

    build_shim(
        sig,
        attrs,
        &Shim {
            moved,
            in_impl,
            export_name,
        },
    )
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

/// Parses the macro's own arguments, all of which are forwarded to `#[wasm_bindgen]`.
fn block_args(attr: TokenStream) -> syn::Result<Punctuated<Meta, Token![,]>> {
    if attr.is_empty() {
        return Ok(Punctuated::new());
    }
    Punctuated::<Meta, Token![,]>::parse_terminated.parse2(attr)
}

/// `#[wasm_export]` on a free function: the original is untouched, and a sibling shim is generated.
fn wasm_export_fn(attr: TokenStream, mut function: ItemFn) -> TokenStream {
    if !function.sig.generics.params.is_empty() {
        return syn::Error::new(
            function.sig.generics.span(),
            "#[wasm_export] does not support generic functions; wasm_bindgen cannot export them",
        )
        .to_compile_error();
    }

    let forwarded = match block_args(attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error(),
    };

    let export_name = match apply_wasm_only(&mut function.attrs, &mut function.sig) {
        Ok(name) => name,
        Err(err) => return err.to_compile_error(),
    };

    if !matches!(function.vis, syn::Visibility::Public(_)) {
        return function.into_token_stream();
    }

    let shim = match take_shim(
        &mut function.attrs,
        &mut function.sig,
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

/// `#[wasm_export]` on an impl block: a second impl block of shims is generated beside it.
fn wasm_export_impl(attr: TokenStream, mut impl_block: ItemImpl) -> TokenStream {
    if !impl_block.generics.params.is_empty() {
        return syn::Error::new(
            impl_block.generics.span(),
            "#[wasm_export] does not support generic impl blocks; wasm_bindgen cannot export them",
        )
        .to_compile_error();
    }

    let bindgen_attr = match block_args(attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error(),
    };

    let self_ty = impl_block.self_ty.clone();
    let mut shims = Vec::new();

    for item in &mut impl_block.items {
        let ImplItem::Fn(method) = item else { continue };

        // Applied before the visibility check so the marker is never silently dropped: on a private
        // method it still renames and deprecates, it just produces no shim.
        let export_name = match apply_wasm_only(&mut method.attrs, &mut method.sig) {
            Ok(name) => name,
            Err(err) => return err.to_compile_error(),
        };

        // Match wasm_bindgen's own rule: every `pub` method in the block is exported. Shimming only
        // the methods that convert something would silently unexport the rest, since this block no
        // longer carries `#[wasm_bindgen]`.
        if !matches!(method.vis, syn::Visibility::Public(_)) {
            continue;
        }

        match take_shim(
            &mut method.attrs,
            &mut method.sig,
            true,
            export_name,
            Punctuated::new(),
        ) {
            Ok(shim) => shims.push(shim),
            Err(err) => return err.to_compile_error(),
        }
    }

    if shims.is_empty() {
        return impl_block.into_token_stream();
    }

    let bindgen_args = (!bindgen_attr.is_empty()).then(|| quote!((#bindgen_attr)));
    // As for a method: the shims have to be configured out with the block they call into.
    let cfgs = impl_block
        .attrs
        .iter()
        .filter(|a| a.path().is_ident("cfg"))
        .cloned()
        .collect::<Vec<_>>();

    quote! {
        #impl_block

        #(#cfgs)*
        #[cfg(feature = "wasm")]
        #[wasm_bindgen #bindgen_args]
        impl #self_ty {
            #(#shims)*
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expansion with the whitespace `TokenStream::to_string` inserts between tokens removed, so
    /// assertions can be written the way the code is.
    fn expand(item: TokenStream) -> String {
        wasm_export(TokenStream::new(), item)
            .to_string()
            .replace(' ', "")
    }

    #[test]
    fn rejects_a_generic_impl_block() {
        // Generic parameters cannot be exported by wasm_bindgen, and `self_ty` already carries
        // them, so generating a second impl block for one would emit `impl Canvas<T><T>`.
        let out = expand(quote! {
            impl<T> Canvas<T> {
                pub fn translate(&self, point: Point) -> Point { point }
            }
        });

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("doesnotsupportgenericimplblocks"), "{out}");
    }

    #[test]
    fn projects_parameters_and_returns_onto_their_wire_types() {
        let out = expand(quote! {
            impl Canvas {
                pub fn translate(&self, point: Point) -> Result<Point, MoveError> { Ok(point) }
            }
        });

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(out.contains("implCanvas{"), "{out}");
        assert!(out.contains("fn__wasm_ts_translate"), "{out}");
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
        let out = expand(quote! {
            impl VaultClient {
                pub fn ciphers(&self) -> CiphersClient { todo!() }
            }
        });

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
        let out = expand(quote! {
            impl Canvas {
                pub fn new() -> Self { Canvas }
                pub fn clone_canvas(&self) -> Canvas { Canvas }
            }
        });

        assert!(
            out.contains("<Selfas::bitwarden_ffi::ToWasm>::Wire"),
            "{out}"
        );
        assert!(
            out.contains("<Canvasas::bitwarden_ffi::ToWasm>::Wire"),
            "{out}"
        );
    }

    #[test]
    fn leaves_reference_parameters_alone() {
        let out = expand(quote! {
            impl Canvas {
                pub fn draw(&self, backend: &JsBackend) -> u32 { 0 }
            }
        });

        assert!(out.contains("backend:&JsBackend"), "{out}");
        assert!(!out.contains("<&JsBackendas"), "{out}");
    }

    #[test]
    fn carries_a_cfg_from_the_impl_block_onto_the_shim_block() {
        let out = expand(quote! {
            #[cfg(feature = "extra")]
            impl Canvas {
                pub fn translate(&self, point: Point) -> Point { point }
            }
        });

        assert_eq!(out.matches("#[cfg(feature=\"extra\")]").count(), 2, "{out}");
    }

    #[test]
    fn carries_a_cfg_from_a_method_onto_its_shim() {
        let out = expand(quote! {
            impl Canvas {
                #[cfg(feature = "extra")]
                pub fn translate(&self, point: Point) -> Point { point }
            }
        });

        assert_eq!(out.matches("#[cfg(feature=\"extra\")]").count(), 2, "{out}");
    }

    #[test]
    fn shims_a_free_function() {
        // No impl block, so the shim calls the function by name rather than through `Self::`.
        let out = expand(quote! {
            pub fn translate(point: Point) -> Result<Point, MoveError> { Ok(point) }
        });

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(
            out.contains("fn__wasm_ts_translate(point:<Pointas::bitwarden_ffi::FromWasm>::Wire"),
            "{out}"
        );
        assert!(out.contains("js_name=\"translate\""), "{out}");
        assert!(out.contains("let__out=translate(point)"), "{out}");
        assert!(!out.contains("Self::translate"), "{out}");
    }

    #[test]
    fn leaves_a_private_free_function_unshimmed() {
        let out = expand(quote! {
            fn translate(point: Point) -> Point { point }
        });

        assert!(!out.contains("__wasm_ts_"), "{out}");
    }
}
