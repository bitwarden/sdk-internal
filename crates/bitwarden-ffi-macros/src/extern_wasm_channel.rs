use darling::{ast::NestedMeta, FromMeta};
use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    parse_quote, spanned::Spanned, Attribute, Error, FnArg, ForeignItem, ForeignItemFn, Ident,
    ItemForeignMod, Pat, ReturnType, Type,
};

fn get_bindgen_attr(item: impl ToTokens, attrs: &[Attribute]) -> Result<&Attribute, Error> {
    for attr in attrs {
        if attr.path().is_ident("wasm_bindgen") {
            return Ok(attr);
        }
    }
    Err(Error::new(
        item.span(),
        "This item needs to use #[wasm_bindgen]",
    ))
}

fn unit_tuple() -> Type {
    parse_quote! { () }
}

struct Func {
    name: Ident,
    args: Vec<(Ident, Type)>,
    return_type: Type,
    returns_value: bool,
}

impl Func {
    fn from_item(func: &ForeignItemFn) -> Result<Func, Error> {
        let name = func.sig.ident.clone();

        let mut args = func.sig.inputs.iter();
        let _this_arg = args.next().expect("Expected a this argument");

        let args = args
            .map(|arg| match arg {
                FnArg::Typed(arg) => match *arg.pat {
                    Pat::Ident(ref pat) => Ok((pat.ident.clone(), (*arg.ty).clone())),
                    _ => Err(Error::new(arg.span(), "Expected an Ident argument")),
                },
                _ => Err(Error::new(arg.span(), "Expected a typed argument")),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let (return_type, returns_value) = match &func.sig.output {
            ReturnType::Default => (unit_tuple(), false),
            ReturnType::Type(_, ty) => ((**ty).clone(), true),
        };

        Ok(Func {
            name,
            args,
            return_type,
            returns_value,
        })
    }
}

#[derive(FromMeta)]
struct WasmIpcArgs {
    trait_impl: Option<syn::TypePath>,
    #[darling(default)]
    async_trait: bool,
}

pub(crate) fn extern_wasm_channel_internal(
    attr: TokenStream,
    item: TokenStream,
) -> Result<TokenStream, Error> {
    let mut input = syn::parse::<ItemForeignMod>(item)?;
    let attr_args = NestedMeta::parse_meta_list(attr.into())?;
    let attr_args = WasmIpcArgs::from_list(&attr_args)?;

    // Validate the ABI
    match input.abi.name {
        Some(ref name) if name.value() == "C" => Ok(()),
        _ => Err(Error::new(input.abi.span(), "Only C ABI is supported")),
    }?;

    // Check that the extern mod is marked with #[wasm_bindgen]
    get_bindgen_attr(&input, &input.attrs)?;

    let mut ident = None;
    let mut functions = Vec::new();

    // Collect and parse the items (one type + multiple functions)
    // For functions that return a value, we need to change the return type to JsValue in the
    // #[wasm_bindgen] extern block, as only types that implement JsCast can be returned.
    // The functions in the Channel struct will return the original values, and just use
    // `serde_wasm_bindgen::from_value`.
    for item in &mut input.items {
        match item {
            ForeignItem::Type(typ) => {
                if ident.is_some() {
                    return Err(Error::new(
                        typ.span(),
                        "Only one type is allowed in a foreign module",
                    ));
                }
                let _bindgen = get_bindgen_attr(&typ, &typ.attrs)?;

                // TODO: Get js_name from the attribute?
                ident = Some(typ.ident.clone());
            }
            ForeignItem::Fn(func) => {
                if let Ok(_bindgen) = get_bindgen_attr(&func, &func.attrs) {
                    // Collect the function info first, then modify the function return type
                    functions.push(Func::from_item(func)?);
                    if let ReturnType::Type(_, ty) = &mut func.sig.output {
                        *ty = parse_quote! { ::wasm_bindgen::JsValue };
                    }
                }
            }
            _ => {
                return Err(Error::new(
                    item.span(),
                    "Only functions and types are supported",
                ));
            }
        }
    }

    let Some(ident) = ident else {
        return Err(Error::new(input.span(), "No type found"));
    };

    // Prepend the ident with Channel
    let channel_ident = Ident::new(&format!("Channel{}", ident), ident.span());
    let channel_command_ident = Ident::new(&format!("Channel{}Command", ident), ident.span());

    // Create the ChannelCommand struct
    let channel_command_variants = functions.iter().map(|f| {
        let name = &f.name;
        let ret = &f.return_type;
        let args = f.args.iter().map(|(ident, typ)| {
            quote::quote! { #ident: #typ }
        });

        quote::quote! { #name {
            // This is the channel used to send the response back to the caller
            _internal_respond_to: ::tokio::sync::oneshot::Sender<#ret>,
            #( #args ),*
        } }
    });

    let impls = functions.iter().map(|f| {
        let name = &f.name;
        let ret = &f.return_type;
        let args = f.args.iter().map(|(ident, typ)| {
            quote::quote! { #ident: #typ }
        });

        let arg_values = f.args.iter().map(|(ident, _)| {
            quote::quote! { #ident }
        });

        let vis = attr_args.trait_impl.is_none().then(|| {
            quote::quote! { pub }
        });

        quote::quote! {
            // TODO: Should these return a result?
            #vis async fn #name(&self, #( #args ),*) -> #ret {
                let (tx, rx) = ::tokio::sync::oneshot::channel();
                self.sender.send(#channel_command_ident::#name {
                    _internal_respond_to: tx,
                    #( #arg_values ),*
                }).await.expect("Failed to send command");
                rx.await.expect("Failed to receive response")
            }
        }
    });

    let channel_impl = if let Some(trait_impl) = &attr_args.trait_impl {
        let async_trait = attr_args.async_trait.then(|| {
            quote::quote! {
                #[async_trait::async_trait]
            }
        });

        quote! {
            #async_trait
            impl #trait_impl for #channel_ident {
                #( #impls )*
            }
        }
    } else {
        quote! {
            impl #channel_ident {
                #( #impls )*
            }
        }
    };

    let matches = functions.iter().map(|f| {
        let name = &f.name;
        let args: Vec<_> = f.args.iter().map(|(ident, _)| {
            quote::quote! { #ident }
        }).collect();

        if f.returns_value {
            // TODO: Should these return a result?
            quote::quote! {
                #channel_command_ident::#name { _internal_respond_to, #( #args ),* } => {
                    let result = self.#name(#( #args ),*).await;
                    let result = serde_wasm_bindgen::from_value(result).expect("Couldn't convert to value");
                    _internal_respond_to.send(result).expect("Failed to send response");
                }
            }
        } else {
            quote::quote! {
                #channel_command_ident::#name { _internal_respond_to, #( #args ),* } => {
                    self.#name(#( #args ),*).await;
                    _internal_respond_to.send(()).expect("Failed to send response");
                }
            }
        }
    });

    Ok(quote::quote! {
        #input

        #[allow(non_camel_case_types, clippy::large_enum_variant)]
        enum #channel_command_ident {
            #( #channel_command_variants ),*
        }

        #[derive(Debug, Clone)]
        pub struct #channel_ident {
            sender: mpsc::Sender<#channel_command_ident>,
        }

        // Define the function that creates the channel impl and the message passing task
        impl #ident {
            fn create_channel_impl(self) -> #channel_ident {
                let (tx, mut rx) = mpsc::channel::<#channel_command_ident>(16);

                wasm_bindgen_futures::spawn_local(async move {
                    while let Some(cmd) = rx.recv().await {
                        match cmd {
                            #( #matches )*
                        }
                    }
                });

                #channel_ident { sender: tx }
            }
        }

    #channel_impl
    }
    .into())
}
