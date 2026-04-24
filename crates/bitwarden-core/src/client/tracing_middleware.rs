//! Middleware for logging HTTP request/response details at TRACE level.
//!
//! Logs request method, URL, headers, request body, and response status and headers.
//! All output is at TRACE level so it is silent unless the subscriber is configured
//! to capture TRACE spans for this crate.
//!
//! Each request is wrapped in an `http_request` span with a unique `request_id`,
//! making it easy to correlate request/response log lines when multiple requests
//! are in flight.
//!
//! Sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`)
//! are redacted in the log output.
//!
//! # Warning
//!
//! At TRACE level this will include request body payloads.
//! Only enable TRACE logging in development environments.

use std::{
    str::from_utf8,
    sync::atomic::{AtomicU32, Ordering},
};

use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next, Result};
use tracing::{Instrument, trace};

const MAX_REQUEST_BODY_LOG_SIZE: usize = 100 * 1024; // 100 KB

const REDACTED_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
];

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

        static REQUEST_ID: AtomicU32 = AtomicU32::new(1);
        let request_id = REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let span = tracing::span!(tracing::Level::TRACE, "http_request", request_id);

        async move {
            trace!(
                method = %req.method(),
                url = %req.url(),
                "HTTP request"
            );

            for (name, value) in req.headers() {
                if is_sensitive(name) {
                    trace!(name = %name, value = "<redacted>", "HTTP request header");
                } else {
                    trace!(name = %name, value = ?value, "HTTP request header");
                }
            }

            if let Some(body) = req.body().and_then(|b| b.as_bytes()) {
                if body.len() > MAX_REQUEST_BODY_LOG_SIZE {
                    trace!(size = body.len(), "HTTP request body (truncated)");
                } else if let Ok(text) = from_utf8(body) {
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
                if is_sensitive(name) {
                    trace!(name = %name, value = "<redacted>", "HTTP response header");
                } else {
                    trace!(name = %name, value = ?value, "HTTP response header");
                }
            }

            Ok(response)
        }
        .instrument(span)
        .await
    }
}

fn is_sensitive(name: &http::HeaderName) -> bool {
    REDACTED_HEADERS.iter().any(|h| name.as_str() == *h)
}
