//! Proc macro for registering `bw` CLI commands into a compile-time inventory.
//!
//! Applied to an args struct with `#[bw_command(path = ..., state = ..., about = ...)]`.
//! Generates an `impl BwCommand` that delegates to the struct's inherent `async fn run` via UFCS,
//! and an `inventory::submit!` that registers the command for CLI assembly at startup.

use darling::FromMeta;
use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

#[derive(Debug, FromMeta)]
struct BwCommandArgs {
    path: String,
    #[darling(default)]
    state: Option<syn::Path>,
    #[darling(default)]
    about: Option<String>,
    #[darling(default)]
    long_about: Option<String>,
    #[darling(default)]
    after_help: Option<String>,
    #[darling(default)]
    todo: bool,
}

/// Registers a CLI command with the `bw` binary's command inventory.
///
/// Applied to a struct that derives `clap::Args`. The struct must also define an inherent method
/// `async fn run(self, state: State) -> CommandResult` (unless `todo` is specified).
///
/// # Attributes
///
/// - `path` (required): whitespace-separated CLI path, e.g. `"sync"` or `"get exposed"`. The first
///   segment determines the group.
/// - `state` (required unless `todo`): one of `LoggedOut` / `LoggedIn` / `Unlocked` / `AnyState`.
/// - `about`, `long_about`, `after_help` (optional): forwarded to the generated `clap::Command`.
/// - `todo` (optional flag): emit a `todo!()` body. Useful for stubbing the CLI surface.
#[proc_macro_attribute]
pub fn bw_command(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = match darling::ast::NestedMeta::parse_meta_list(attr.into()) {
        Ok(metas) => match BwCommandArgs::from_list(&metas) {
            Ok(a) => a,
            Err(e) => return TokenStream::from(e.write_errors()),
        },
        Err(e) => return TokenStream::from(darling::Error::from(e).write_errors()),
    };

    let input = parse_macro_input!(item as DeriveInput);
    let struct_ident = &input.ident;

    let path_segments: Vec<&str> = args.path.split_whitespace().collect();
    if path_segments.is_empty() {
        return syn::Error::new_spanned(&input, "bw_command: `path` must be non-empty")
            .to_compile_error()
            .into();
    }
    let leaf_name = path_segments
        .last()
        .expect("non-empty, checked above")
        .to_string();
    let path_literals = path_segments.iter().map(|s| quote!(#s));

    if !args.todo && args.state.is_none() {
        return syn::Error::new_spanned(
            &input,
            "bw_command: `state` is required unless `todo` is set",
        )
        .to_compile_error()
        .into();
    }

    // Builder chain for clap::Command augmentation.
    let about_call = args.about.as_ref().map(|s| quote!(.about(#s)));
    let long_about_call = args.long_about.as_ref().map(|s| quote!(.long_about(#s)));
    let after_help_call = args.after_help.as_ref().map(|s| quote!(.after_help(#s)));

    let bw_command_impl = if args.todo {
        let state = args
            .state
            .clone()
            .unwrap_or_else(|| syn::parse_quote!(crate::client_state::AnyState));
        quote! {
            impl crate::client_state::BwCommand for #struct_ident {
                type Client = #state;
                async fn run(self, _client: #state) -> crate::render::CommandResult {
                    ::std::todo!(concat!("Implement ", stringify!(#struct_ident)))
                }
            }
        }
    } else {
        let state = args
            .state
            .clone()
            .expect("checked above that state is required unless todo");
        quote! {
            impl crate::client_state::BwCommand for #struct_ident {
                type Client = #state;
                async fn run(self, client: #state) -> crate::render::CommandResult {
                    // UFCS to call the inherent `run` method rather than this trait method.
                    <#struct_ident>::run(self, client).await
                }
            }
        }
    };

    let expanded = quote! {
        #input

        #bw_command_impl

        ::inventory::submit! {
            crate::cli_runtime::BwCommandEntry {
                path: &[#(#path_literals),*],
                augment: |parent: ::clap::Command| -> ::clap::Command {
                    let leaf = <#struct_ident as ::clap::Args>::augment_args(
                        ::clap::Command::new(#leaf_name)
                    )
                    #about_call
                    #long_about_call
                    #after_help_call;
                    parent.subcommand(leaf)
                },
                dispatch: |matches: &::clap::ArgMatches, ctx: crate::client_state::ClientContext|
                    -> ::std::pin::Pin<
                        ::std::boxed::Box<
                            dyn ::std::future::Future<Output = crate::render::CommandResult>
                        >
                    >
                {
                    // Parse synchronously before returning the future so the future is not tied
                    // to the `matches` reference's lifetime.
                    let parsed = <#struct_ident as ::clap::FromArgMatches>::from_arg_matches(matches)
                        .map_err(|e| ::color_eyre::eyre::eyre!(e.to_string()));
                    ::std::boxed::Box::pin(async move {
                        let args = parsed?;
                        let client = ::std::convert::TryInto::try_into(ctx)?;
                        <#struct_ident as crate::client_state::BwCommand>::run(args, client).await
                    })
                },
            }
        }
    };

    TokenStream::from(expanded)
}
