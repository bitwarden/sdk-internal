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

    /// Create a new Bitwarden client with a custom token handler and additional
    /// middleware to be chained before authentication middleware.
    ///
    /// # Arguments
    ///
    /// * `settings` - Optional client configuration
    /// * `token_handler` - Token handler for authentication middleware
    /// * `additional_middleware` - Extra middleware chained outermost (before auth)
    pub fn new_with_token_handler_and_middleware(
        settings: Option<ClientSettings>,
        token_handler: Arc<dyn TokenHandler>,
        additional_middleware: Vec<Arc<dyn reqwest_middleware::Middleware>>,
    ) -> Self {
        let mut builder = ClientBuilder::new()
            .with_token_handler(token_handler)
            .with_middleware(additional_middleware);
        if let Some(s) = settings {
            builder = builder.with_settings(s);
        }
        builder.build()
    }

    /// Returns a [`ClientBuilder`] for constructing a new [`Client`].
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::auth::auth_tokens::NoopTokenHandler;

    #[test]
    fn new_with_token_handler_and_middleware_compiles() {
        struct StubMiddleware;

        #[async_trait::async_trait]
        impl reqwest_middleware::Middleware for StubMiddleware {
            async fn handle(
                &self,
                req: reqwest::Request,
                extensions: &mut http::Extensions,
                next: reqwest_middleware::Next<'_>,
            ) -> reqwest_middleware::Result<reqwest::Response> {
                next.run(req, extensions).await
            }
        }

        let arc_middleware: Arc<dyn reqwest_middleware::Middleware> = Arc::new(StubMiddleware);
        let _client = Client::new_with_token_handler_and_middleware(
            None,
            Arc::new(NoopTokenHandler),
            vec![arc_middleware],
        );
    }
}
