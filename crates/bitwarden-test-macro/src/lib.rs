//! Proc macro for Play test framework
//!
//! Provides the `#[play_test]` attribute macro for writing E2E tests with automatic
//! Play instance setup and cleanup.

use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

/// Attribute macro for Play framework tests
///
/// Transforms an async test function that takes a `Play` parameter into a properly
/// configured tokio test with automatic cleanup.
///
/// # Example
///
/// ```ignore
/// use bitwarden_test::play::{play_test, Play, SingleUserArgs, SingleUserScene};
///
/// #[play_test]
/// async fn test_user_login(play: Play) {
///     let args = SingleUserArgs {
///         email: "test@example.com".to_string(),
///         ..Default::default()
///     };
///     let scene = play.scene::<SingleUserScene>(&args).await.unwrap();
///     // Cleanup happens automatically when the test completes
/// }
/// ```
///
/// The macro transforms the above into:
///
/// ```ignore
/// #[tokio::test]
/// async fn test_user_login() {
///     ::bitwarden_test::play::Play::builder()
///         .run(|play: Play| async move {
///             // original test body
///         })
///         .await;
/// }
/// ```
#[proc_macro_attribute]
pub fn play_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);

    let fn_name = &input.sig.ident;
    let fn_body = &input.block;
    let fn_vis = &input.vis;
    let fn_attrs = &input.attrs;

    // Extract the play parameter name and type from the function signature
    let (play_param, play_type) = input
        .sig
        .inputs
        .first()
        .and_then(|arg| {
            if let syn::FnArg::Typed(pat_type) = arg
                && let syn::Pat::Ident(pat_ident) = &*pat_type.pat
            {
                return Some((pat_ident.ident.clone(), pat_type.ty.clone()));
            }
            None
        })
        .unwrap_or_else(|| {
            let ident = syn::Ident::new("play", proc_macro2::Span::call_site());
            let ty: syn::Type = syn::parse_quote!(::bitwarden_test::play::Play);
            (ident, Box::new(ty))
        });

    let expanded = quote! {
        #(#fn_attrs)*
        #[::tokio::test]
        #fn_vis async fn #fn_name() {
            ::bitwarden_test::play::Play::builder()
                .run(|#play_param: #play_type| async move #fn_body)
                .await;
        }
    };

    TokenStream::from(expanded)
}
