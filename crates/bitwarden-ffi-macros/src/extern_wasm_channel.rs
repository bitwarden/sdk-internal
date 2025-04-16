use darling::{ast::NestedMeta, FromMeta};
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    parse_quote, spanned::Spanned, Attribute, Error, FnArg, ForeignItem, ForeignItemFn, Ident,
    ItemForeignMod, Pat, ReturnType, Type,
};

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
    let mut input = syn::parse2::<ItemForeignMod>(item)?;
    let attr_args = NestedMeta::parse_meta_list(attr)?;
    let attr_args = WasmIpcArgs::from_list(&attr_args)?;

    // Validate the ABI
    match input.abi.name {
        Some(ref name) if name.value() == "C" => Ok(()),
        _ => Err(Error::new(input.abi.span(), "Only C ABI is supported")),
    }?;

    // Check that the extern mod is marked with #[wasm_bindgen]
    get_bindgen_attr(&input, &input.attrs)?;

    // Extract the type and functions from the foreign module.
    // This will also transform the functions to use JsValue as the return type for the extern
    // block.
    let Items { ident, functions } = Items::process_items(&mut input)?;

    // Prepend the ident with Channel
    let channel_ident = quote::format_ident!("Channel{ident}");
    let channel_command_ident = quote::format_ident!("Channel{ident}Command");

    // Generate the command struct used in the sent messages between the WASM implementation and the
    // IPC implementation
    let command_struct = generate_command_struct(&channel_command_ident, &functions);

    // Generate all the functions in the IPC implementation that will call the WASM impl through
    // channels
    let channel_impl = generate_channel_impl(
        &channel_ident,
        &channel_command_ident,
        &functions,
        &attr_args,
    );

    // Generate the function that, given a WASM instance, creates the channel implementation, and
    // starts the message passing task
    let channel_init =
        generate_channel_init(&ident, &channel_ident, &channel_command_ident, &functions);

    // Define the channel based IPC struct
    let channel_struct = quote::quote! {
        #[derive(Debug, Clone)]
        pub struct #channel_ident {
            sender: ::tokio::sync::mpsc::Sender<#channel_command_ident>,
        }
    };

    Ok([
        input.into_token_stream(),
        command_struct,
        channel_struct,
        channel_init,
        channel_impl,
    ]
    .into_iter()
    .collect())
}

fn generate_command_struct(channel_ident: &Ident, functions: &[Func]) -> TokenStream {
    // Create one variant per function, with all the arguments, plus a return channel
    let enum_variants = functions.iter().map(|f| {
        let name = &f.name;
        let ret = &f.return_type;
        let args_decls = &f.args_decls;

        quote::quote! { #name {
            // This is the tokio channel used to send the response back to the caller.
            // Using an _internal_ prefix to try to avoid collisions.
            _internal_respond_to: ::tokio::sync::oneshot::Sender<#ret>,
            #( #args_decls ),*
        } }
    });

    quote::quote! {
        #[allow(non_camel_case_types, clippy::large_enum_variant)]
        enum #channel_ident {
            #( #enum_variants ),*
        }
    }
}

fn generate_channel_impl(
    channel_ident: &Ident,
    channel_command_ident: &Ident,
    functions: &[Func],
    attr_args: &WasmIpcArgs,
) -> TokenStream {
    let impls = functions.iter().map(|f| {
        let name = &f.name;
        let ret = &f.return_type;
        let arg_idents = &f.arg_idents;
        let args_decls = &f.args_decls;

        let vis = attr_args.trait_impl.is_none().then(|| {
            quote::quote! { pub }
        });

        quote::quote! {
            // TODO: Should these return a result?
            #vis async fn #name(&self, #( #args_decls ),*) -> #ret {
                let (tx, rx) = ::tokio::sync::oneshot::channel();

                self.sender.send(#channel_command_ident::#name {
                    _internal_respond_to: tx,
                    #( #arg_idents ),*
                }).await.expect("Failed to send command");

                rx.await.expect("Failed to receive response")
            }
        }
    });

    if let Some(trait_impl) = &attr_args.trait_impl {
        let async_trait = attr_args.async_trait.then(|| {
            quote::quote! { #[async_trait::async_trait] }
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
    }
}

fn generate_channel_init(
    ident: &Ident,
    channel_ident: &Ident,
    channel_command_ident: &Ident,
    functions: &[Func],
) -> TokenStream {
    let matches = functions.iter().map(|f| {
        let name = &f.name;
        let arg_idents = &f.arg_idents;

        if f.returns_value {
            // TODO: Should these return a result?
            quote::quote! {
                #channel_command_ident::#name { _internal_respond_to, #( #arg_idents ),* } => {
                    let result = self.#name(#( #arg_idents ),*).await;
                    let result = serde_wasm_bindgen::from_value(result).expect("Couldn't convert to value");
                    _internal_respond_to.send(result).expect("Failed to send response");
                }
            }
        } else {
            quote::quote! {
                #channel_command_ident::#name { _internal_respond_to, #( #arg_idents ),* } => {
                    self.#name(#( #arg_idents ),*).await;
                    _internal_respond_to.send(()).expect("Failed to send response");
                }
            }
        }
    });

    quote::quote! {
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
    }
}

fn get_bindgen_attr(item: impl ToTokens, attrs: &[Attribute]) -> Result<&Attribute, Error> {
    attrs
        .iter()
        .find(|a| a.path().is_ident("wasm_bindgen"))
        .ok_or_else(|| Error::new(item.span(), "This item needs to use #[wasm_bindgen]"))
}

struct Items {
    ident: Ident,
    functions: Vec<Func>,
}

struct Func {
    name: Ident,
    arg_idents: Vec<Ident>,
    args_decls: Vec<TokenStream>,
    return_type: Type,
    returns_value: bool,
}

impl Items {
    fn process_items(input: &mut ItemForeignMod) -> Result<Items, Error> {
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

        Ok(Items { ident, functions })
    }
}

impl Func {
    fn from_item(func: &ForeignItemFn) -> Result<Func, Error> {
        let name = func.sig.ident.clone();

        let mut args = func.sig.inputs.iter();
        let _this_arg = args.next().expect("Expected a this argument");

        let mut arg_idents = Vec::new();
        let mut args_decls = Vec::new();

        for arg in args {
            match arg {
                FnArg::Typed(arg) => match *arg.pat {
                    Pat::Ident(ref pat) => {
                        let ident = pat.ident.clone();
                        let ty = &arg.ty;
                        args_decls.push(quote::quote! { #ident: #ty });
                        arg_idents.push(ident);
                    }
                    _ => return Err(Error::new(arg.span(), "Expected an Ident argument")),
                },
                _ => return Err(Error::new(arg.span(), "Expected a typed argument")),
            }
        }

        let (return_type, returns_value) = match &func.sig.output {
            ReturnType::Default => (parse_quote! { () }, false),
            ReturnType::Type(_, ty) => ((**ty).clone(), true),
        };

        Ok(Func {
            name,
            arg_idents,
            args_decls,
            return_type,
            returns_value,
        })
    }
}
