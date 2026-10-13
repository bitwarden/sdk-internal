use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{
    Attribute, FnArg, ForeignItem, ForeignItemFn, ItemForeignMod, Meta, Pat, Type, parse2,
    spanned::Spanned,
};

use crate::{
    attrs::{self, Args},
    wire::{crosses_bare, split_result, to_wire_type},
};

/// `wasm_bindgen` arguments under which renaming an import would change what it binds to, so an
/// import carrying one is left as written.
const KEEPS_ITS_NAME: &[&str] = &[
    "constructor",
    "getter",
    "setter",
    "indexing_getter",
    "indexing_setter",
    "indexing_deleter",
    "variadic",
];

/// Declares a block of JavaScript imports, forwarding this macro's arguments to `#[wasm_bindgen]`,
/// and implements the wire traits for each `type` it declares so the type crosses as itself.
///
/// A `catch` import whose parameters need converting is renamed to a hidden `__wasm_raw_*` import
/// that takes the wire types, and a wrapper with the original signature converts and calls it.
pub(crate) fn wasm_import(attr: TokenStream, item: TokenStream) -> TokenStream {
    let forwarded = match attrs::parse_args(attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error(),
    };

    let mut block = match parse2::<ItemForeignMod>(item.clone()) {
        Ok(block) => block,
        Err(_) => {
            return syn::Error::new_spanned(
                item,
                "#[wasm_import] applies to an `extern \"C\"` block",
            )
            .to_compile_error();
        }
    };

    if let Some(attr) = attrs::find_wasm_bindgen(&block.attrs) {
        return syn::Error::new_spanned(attr, "#[wasm_import] replaces #[wasm_bindgen]; remove it")
            .to_compile_error();
    }

    // The block's own `cfg`s gate the generated items too, or they would name a type that does not
    // exist.
    let cfgs: Vec<_> = block
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg"))
        .cloned()
        .collect();
    let wire_impls: Vec<_> = block
        .items
        .iter()
        .filter_map(|item| match item {
            ForeignItem::Type(ty) => {
                let ident = &ty.ident;
                Some(quote! {
                    #(#cfgs)*
                    ::bitwarden_ffi::impl_wire_object!(#ident);
                })
            }
            _ => None,
        })
        .collect();

    let mut wrappers = Vec::new();
    for item in &mut block.items {
        let ForeignItem::Fn(function) = item else {
            continue;
        };
        match wrap_import(function) {
            Ok(Some(wrapper)) => wrappers.push(quote! {
                #(#cfgs)*
                #wrapper
            }),
            Ok(None) => {}
            Err(err) => return err.to_compile_error(),
        }
    }

    let call = if forwarded.is_empty() {
        quote!(wasm_bindgen)
    } else {
        quote!(wasm_bindgen(#forwarded))
    };
    let body = block.to_token_stream();
    // Unconditional, unlike the other macros: a `type` in an extern block only compiles once
    // wasm_bindgen rewrites it, and some blocks are gated on `target_arch` rather than `wasm`.
    quote! {
        #[::wasm_bindgen::prelude::#call]
        #body

        #(#wire_impls)*

        #(#wrappers)*
    }
}

/// How a wrapper reaches the import it wraps.
enum Callee {
    /// A `method` import: the wrapper is a method on the receiver's type.
    Method { self_ty: Type, by_ref: bool },
    /// A `static_method_of = Class` import: the wrapper is an associated function of `Class`.
    Static(syn::Path),
    /// A free function.
    Free,
}

/// Renames a `catch` import whose parameters need converting and returns the wrapper that converts
/// them, or `None` to leave the import as written.
fn wrap_import(function: &mut ForeignItemFn) -> syn::Result<Option<TokenStream>> {
    let args: Args = function
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("wasm_bindgen"))
        .filter_map(attrs::wasm_bindgen_args)
        .flatten()
        .collect();
    let has = |name: &str| args.iter().any(|meta| meta.path().is_ident(name));

    // Without `catch` a wrapper has nowhere to report a failed conversion.
    if !has("catch") || KEEPS_ITS_NAME.iter().any(|name| has(name)) {
        return Ok(None);
    }
    let syn::ReturnType::Type(_, ret) = &function.sig.output else {
        return Ok(None);
    };
    if split_result(ret).is_none() {
        return Ok(None);
    }
    if !function.sig.generics.params.is_empty() {
        return Ok(None);
    }

    let mut inputs = function.sig.inputs.iter_mut();
    let callee = if has("method") {
        let Some(FnArg::Typed(this)) = inputs.next() else {
            return Ok(None);
        };
        match &*this.ty {
            Type::Reference(reference) => Callee::Method {
                self_ty: (*reference.elem).clone(),
                by_ref: true,
            },
            ty => Callee::Method {
                self_ty: ty.clone(),
                by_ref: false,
            },
        }
    } else if let Some(class) = args.iter().find_map(|meta| match meta {
        Meta::NameValue(nv) if nv.path.is_ident("static_method_of") => match &nv.value {
            syn::Expr::Path(path) => Some(path.path.clone()),
            _ => None,
        },
        _ => None,
    }) {
        Callee::Static(class)
    } else {
        Callee::Free
    };

    let mut params = Vec::new();
    let mut conversions = Vec::new();
    let mut call_args = Vec::new();
    for (i, input) in inputs.enumerate() {
        let FnArg::Typed(pat_type) = input else {
            return Ok(None);
        };
        let name = match &*pat_type.pat {
            Pat::Ident(pat) => pat.ident.clone(),
            _ => syn::Ident::new(&format!("__arg{i}"), pat_type.pat.span()),
        };
        let ty = (*pat_type.ty).clone();
        params.push(quote!(#name: #ty));
        call_args.push(quote!(#name));
        if !crosses_bare(&ty) {
            conversions.push(quote! {
                let #name = <#ty as ::bitwarden_ffi::ToWasm>::to_wire(#name)
                    .map_err(::bitwarden_ffi::import_conversion_error)?;
            });
            let wire = to_wire_type(&ty);
            *pat_type.ty = syn::parse_quote!(#wire);
            *pat_type.pat = syn::parse_quote!(#name);
        }
    }

    // Nothing to convert, so the import already has the signature a wrapper would give it.
    if conversions.is_empty() {
        return Ok(None);
    }

    let name = function.sig.ident.clone();
    let raw = syn::Ident::new(&format!("__wasm_raw_{name}"), name.span());
    if !has("js_name") {
        let js_name = name.to_string();
        function
            .attrs
            .push(syn::parse_quote!(#[wasm_bindgen(js_name = #js_name)]));
    }
    function.sig.ident = raw.clone();
    let vis = std::mem::replace(&mut function.vis, syn::Visibility::Inherited);
    // Docs move to the wrapper, which is what callers see; `cfg`s apply to both.
    let (docs, kept): (Vec<Attribute>, Vec<Attribute>) = std::mem::take(&mut function.attrs)
        .into_iter()
        .partition(|attr| attr.path().is_ident("doc"));
    function.attrs = kept;
    function.attrs.push(syn::parse_quote!(#[doc(hidden)]));
    let fn_cfgs = function
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg"));

    let is_async = function.sig.asyncness.is_some();
    let async_tok = is_async.then(|| quote!(async));
    let await_tok = is_async.then(|| quote!(.await));
    let output = &function.sig.output;

    Ok(Some(match callee {
        Callee::Method { self_ty, by_ref } => {
            let receiver = if by_ref { quote!(&self) } else { quote!(self) };
            quote! {
                impl #self_ty {
                    #(#docs)*
                    #(#fn_cfgs)*
                    #vis #async_tok fn #name(#receiver, #(#params),*) #output {
                        #(#conversions)*
                        self.#raw(#(#call_args),*)#await_tok
                    }
                }
            }
        }
        Callee::Static(class) => quote! {
            impl #class {
                #(#docs)*
                #(#fn_cfgs)*
                #vis #async_tok fn #name(#(#params),*) #output {
                    #(#conversions)*
                    Self::#raw(#(#call_args),*)#await_tok
                }
            }
        },
        Callee::Free => quote! {
            #(#docs)*
            #(#fn_cfgs)*
            #vis #async_tok fn #name(#(#params),*) #output {
                #(#conversions)*
                #raw(#(#call_args),*)#await_tok
            }
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand(attr: TokenStream, item: TokenStream) -> String {
        wasm_import(attr, item).to_string().replace(' ', "")
    }

    #[test]
    fn applies_wasm_bindgen_and_implements_the_wire_traits_per_type() {
        let out = expand(
            TokenStream::new(),
            quote! {
                extern "C" {
                    pub type Driver;
                    pub type Signal;

                    #[wasm_bindgen(method)]
                    pub fn lock(this: &Driver);
                }
            },
        );

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(
            out.contains("#[::wasm_bindgen::prelude::wasm_bindgen]"),
            "{out}"
        );
        assert!(
            out.contains("::bitwarden_ffi::impl_wire_object!(Driver);"),
            "{out}"
        );
        assert!(
            out.contains("::bitwarden_ffi::impl_wire_object!(Signal);"),
            "{out}"
        );
        assert!(!out.contains("impl_wire_object!(lock)"), "{out}");
    }

    #[test]
    fn forwards_arguments_to_wasm_bindgen() {
        let out = expand(
            quote!(module = "/js/driver.js"),
            quote! {
                extern "C" {
                    pub type Driver;
                }
            },
        );

        assert!(
            out.contains("#[::wasm_bindgen::prelude::wasm_bindgen(module=\"/js/driver.js\")]"),
            "{out}"
        );
    }

    #[test]
    fn gates_the_wire_impls_on_the_blocks_cfg() {
        let out = expand(
            TokenStream::new(),
            quote! {
                #[cfg(target_arch = "wasm32")]
                extern "C" {
                    pub type Driver;
                }
            },
        );

        assert!(
            out.contains(
                "#[cfg(target_arch=\"wasm32\")]::bitwarden_ffi::impl_wire_object!(Driver);"
            ),
            "{out}"
        );
    }

    #[test]
    fn a_block_without_types_implements_nothing() {
        let out = expand(
            TokenStream::new(),
            quote! {
                extern "C" {
                    pub fn log(message: &str);
                }
            },
        );

        assert!(!out.contains("impl_wire_object"), "{out}");
    }

    #[test]
    fn wraps_a_catch_method_that_converts_a_parameter() {
        let out = expand(
            TokenStream::new(),
            quote! {
                extern "C" {
                    pub type Driver;

                    /// Locks the user.
                    #[wasm_bindgen(method, catch)]
                    pub async fn lock(this: &Driver, user_id: UserId) -> Result<(), JsValue>;
                }
            },
        );

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(
            out.contains(
                "fn__wasm_raw_lock(this:&Driver,user_id:<UserIdas::bitwarden_ffi::ToWasm>::Wire)"
            ),
            "{out}"
        );
        assert!(out.contains("#[wasm_bindgen(js_name=\"lock\")]"), "{out}");
        assert!(
            out.contains(
                "implDriver{#[doc=r\"Lockstheuser.\"]pubasyncfnlock(&self,user_id:UserId)"
            ),
            "{out}"
        );
        assert!(out.contains("<UserIdas::bitwarden_ffi::ToWasm>::to_wire(user_id).map_err(::bitwarden_ffi::import_conversion_error)?;"), "{out}");
        assert!(out.contains("self.__wasm_raw_lock(user_id).await"), "{out}");
    }

    #[test]
    fn keeps_an_existing_js_name() {
        let out = expand(
            TokenStream::new(),
            quote! {
                extern "C" {
                    pub type Driver;

                    #[wasm_bindgen(method, catch, js_name = provideTotp)]
                    fn provide_totp(this: &Driver, attempt: u32) -> Result<JsValue, JsValue>;
                }
            },
        );

        assert!(out.contains("fn__wasm_raw_provide_totp"), "{out}");
        assert!(!out.contains("js_name=\"provide_totp\""), "{out}");
    }

    #[test]
    fn calls_a_static_method_through_its_class() {
        let out = expand(
            TokenStream::new(),
            quote! {
                extern "C" {
                    pub type Store;

                    #[wasm_bindgen(static_method_of = Store, catch)]
                    pub fn open(name: Name) -> Result<Store, JsValue>;
                }
            },
        );

        assert!(out.contains("implStore{pubfnopen(name:Name)"), "{out}");
        assert!(out.contains("Self::__wasm_raw_open(name)"), "{out}");
    }

    #[test]
    fn calls_a_free_function_directly() {
        let out = expand(
            TokenStream::new(),
            quote! {
                extern "C" {
                    #[wasm_bindgen(catch, js_namespace = JSON)]
                    fn stringify(value: Point) -> Result<JsValue, JsValue>;
                }
            },
        );

        assert!(
            out.contains("fnstringify(value:Point)->Result<JsValue,JsValue>"),
            "{out}"
        );
        assert!(out.contains("__wasm_raw_stringify(value)"), "{out}");
    }

    #[test]
    fn leaves_an_import_without_catch_alone() {
        let out = expand(
            TokenStream::new(),
            quote! {
                extern "C" {
                    pub type Driver;

                    #[wasm_bindgen(method)]
                    pub fn lock(this: &Driver, user_id: UserId);
                }
            },
        );

        assert!(!out.contains("__wasm_raw_"), "{out}");
    }

    #[test]
    fn leaves_an_import_that_takes_only_references_alone() {
        let out = expand(
            TokenStream::new(),
            quote! {
                extern "C" {
                    pub type Driver;

                    #[wasm_bindgen(method, catch)]
                    pub fn log(this: &Driver, message: &str) -> Result<(), JsValue>;
                }
            },
        );

        assert!(!out.contains("__wasm_raw_"), "{out}");
    }

    #[test]
    fn leaves_a_getter_alone() {
        let out = expand(
            TokenStream::new(),
            quote! {
                extern "C" {
                    pub type Driver;

                    #[wasm_bindgen(method, getter, catch)]
                    pub fn name(this: &Driver) -> Result<String, JsValue>;

                    #[wasm_bindgen(method, setter, catch)]
                    pub fn set_name(this: &Driver, name: String) -> Result<(), JsValue>;
                }
            },
        );

        assert!(!out.contains("__wasm_raw_"), "{out}");
    }

    #[test]
    fn gates_a_wrapper_on_the_blocks_cfg() {
        let out = expand(
            TokenStream::new(),
            quote! {
                #[cfg(target_arch = "wasm32")]
                extern "C" {
                    pub type Driver;

                    #[wasm_bindgen(method, catch)]
                    pub fn lock(this: &Driver, user_id: UserId) -> Result<(), JsValue>;
                }
            },
        );

        assert!(
            out.contains("#[cfg(target_arch=\"wasm32\")]implDriver{"),
            "{out}"
        );
    }

    #[test]
    fn rejects_an_item_that_is_not_an_extern_block() {
        let out = expand(TokenStream::new(), quote! { pub struct Driver; });

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("appliestoan`extern\\\"C\\\"`block"), "{out}");
    }

    #[test]
    fn rejects_a_block_that_already_has_wasm_bindgen() {
        let out = expand(
            TokenStream::new(),
            quote! {
                #[wasm_bindgen]
                extern "C" {
                    pub type Driver;
                }
            },
        );

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("replaces#[wasm_bindgen]"), "{out}");
    }
}
