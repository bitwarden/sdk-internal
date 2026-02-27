//! HTTP middleware for attaching ServerCommunicationConfig cookies to requests.
//!
//! This middleware integrates with reqwest_middleware to intercept HTTP requests,
//! query ServerCommunicationConfigClient for cookies based on request hostname,
//! and attach them as Cookie headers per RFC 6265.

use std::sync::Arc;

use crate::{
    ServerCommunicationConfigClient, ServerCommunicationConfigPlatformApi,
    ServerCommunicationConfigRepository,
};

/// Middleware that attaches ServerCommunicationConfig cookies to HTTP requests.
///
/// This middleware queries ServerCommunicationConfigClient for cookies based on the
/// request's destination hostname and attaches them as a Cookie header. Cookie values
/// are formatted per RFC 6265 (semicolon-separated name=value pairs).
///
/// # Error Handling
///
/// This middleware follows warn-and-continue error handling per ADR-058. If cookie
/// retrieval or header formatting fails, the middleware logs a warning and allows
/// the request to proceed without cookies. This ensures that transient cookie errors
/// do not fail requests.
///
/// # Middleware Ordering
///
/// Per ADR-056, this middleware should be registered BEFORE authentication middleware
/// in the ClientBuilder chain. Cookies are transport-level session affinity hints that
/// do not depend on authentication state.
pub struct ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    #[allow(dead_code)]
    client: Arc<ServerCommunicationConfigClient<R, P>>,
}

impl<R, P> ServerCommunicationConfigMiddleware<R, P>
where
    R: ServerCommunicationConfigRepository,
    P: ServerCommunicationConfigPlatformApi,
{
    /// Creates a new ServerCommunicationConfigMiddleware.
    ///
    /// # Arguments
    ///
    /// * `client` - The ServerCommunicationConfigClient that provides cookie retrieval
    pub fn new(client: Arc<ServerCommunicationConfigClient<R, P>>) -> Self {
        Self { client }
    }
}
