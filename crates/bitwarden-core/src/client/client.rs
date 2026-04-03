use std::sync::Arc;

use super::internal::InternalClient;
use crate::{
    auth::auth_tokens::TokenHandler,
    client::{builder::ClientBuilder, client_settings::ClientSettings},
};

/// The main struct to interact with the Bitwarden SDK.
#[derive(Clone)]
pub struct Client {
    // Important: The [`Client`] struct requires its `Clone` implementation to return an owned
    // reference to the same instance. This is required to properly use the FFI API, where we can't
    // just use normal Rust references effectively. For this to happen, any mutable state needs
    // to be behind an Arc, ideally as part of the existing [`InternalClient`] struct.
    #[doc(hidden)]
    pub internal: Arc<InternalClient>,
}

impl Client {
    /// Create a new Bitwarden client with default settings and a no-op token handler.
    pub fn new(settings: Option<ClientSettings>) -> Self {
        let mut builder = ClientBuilder::new();
        if let Some(s) = settings {
            builder = builder.with_settings(s);
        }
        builder.build()
    }

    /// Create a new Bitwarden client with the specified token handler for managing authentication
    /// tokens.
    pub fn new_with_token_handler(
        settings: Option<ClientSettings>,
        token_handler: Arc<dyn TokenHandler>,
    ) -> Self {
        let mut builder = ClientBuilder::new().with_token_handler(token_handler);
        if let Some(s) = settings {
            builder = builder.with_settings(s);
        }
        builder.build()
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }
}
