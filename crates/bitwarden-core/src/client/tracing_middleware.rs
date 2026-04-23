//! Middleware for logging HTTP request/response details at TRACE level.
//!
//! Logs request method, URL, headers, request body, and response status and headers.
//! All output is at TRACE level so it is silent unless the subscriber is configured
//! to capture TRACE spans for this crate.
//!
//! # Warning
//!
//! At TRACE level this will include sensitive data such as authorization headers.
//! Only enable TRACE logging in development environments.

use std::str::from_utf8;

use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next, Result};
use tracing::trace;

/// Reqwest middleware that logs HTTP request and response details via `tracing` at TRACE level.
pub struct ReqwestTracingMiddleware;

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl Middleware for ReqwestTracingMiddleware {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> Result<Response> {
        if !tracing::enabled!(tracing::Level::TRACE) {
            return next.run(req, extensions).await;
        }

        trace!(
            method = %req.method(),
            url = %req.url(),
            "HTTP request"
        );

        for (name, value) in req.headers() {
            trace!(
                name = %name,
                value = ?value,
                "HTTP request header"
            );
        }

        if let Some(body) = req.body().and_then(|b| b.as_bytes()) {
            if let Ok(text) = from_utf8(body) {
                trace!(body = %text, "HTTP request body");
            } else {
                trace!(size = body.len(), "HTTP request body (binary)");
            }
        }

        let response = next.run(req, extensions).await?;

        trace!(
            status = %response.status(),
            "HTTP response"
        );

        for (name, value) in response.headers() {
            trace!(
                name = %name,
                value = ?value,
                "HTTP response header"
            );
        }

        Ok(response)
    }
}
