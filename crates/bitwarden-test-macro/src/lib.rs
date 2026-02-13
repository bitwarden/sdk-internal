//! Proc macros for Bitwarden test framework
//!
//! Provides:
//! - `#[play_test]` attribute macro for writing E2E tests with automatic Play instance setup and
//!   cleanup.
//! - `#[from_client]` attribute macro for generating `from_client` methods on client structs.

mod from_client;
mod play;

use proc_macro::TokenStream;

/// Attribute macro for Play framework tests.
///
/// See [`play::play_test`] for documentation.
#[proc_macro_attribute]
pub fn play_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    play::play_test(attr, item)
}

/// Attribute macro for generating `from_client` methods on client structs.
///
/// See [`from_client::from_client`] for documentation.
#[proc_macro_attribute]
pub fn from_client(attr: TokenStream, item: TokenStream) -> TokenStream {
    from_client::from_client(attr, item)
}
