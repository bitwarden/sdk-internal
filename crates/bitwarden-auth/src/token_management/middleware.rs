//! Shared utilities for token renewal.

use bitwarden_api_api::apis::AuthRequired;
use bitwarden_core::auth::login::LoginError;
use reqwest_middleware::Middleware;

pub(crate) const TOKEN_RENEW_MARGIN_SECONDS: i64 = 5 * 60;

/// A wrapper that implements [reqwest_middleware::Middleware] by delegating to a [MiddlewareExt]
/// for token retrieval. We can't implement [Middleware] directly on [MiddlewareExt] because
/// [Middleware] is defined in an external crate, so we use this wrapper to bridge between them.
pub(crate) struct MiddlewareWrapper<T>(pub(crate) T);

/// Trait used to share over the token attaching middleware. This is implemented by the token
/// management structs, leaving them responsible for handling token retrieval and renewal logic. The
/// middleware simply calls [MiddlewareExt::get_token] to get the current token (renewing if
/// necessary) and attaches it to the request.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub(crate) trait MiddlewareExt: 'static + Send + Sync {
    async fn get_token(&self) -> Result<Option<String>, LoginError>;
}

/// Implements HTTP middleware that attaches authentication tokens to requests.
/// Delegates to [MiddlewareExt::get_token] to retrieve tokens (which handles renewal).
/// Only applies to requests marked with [AuthRequired].
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<T: MiddlewareExt> Middleware for MiddlewareWrapper<T> {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        match ext.get::<AuthRequired>() {
            Some(AuthRequired::Bearer) => {
                match self.0.get_token().await {
                    Ok(Some(token)) => match format!("Bearer {}", token).parse() {
                        Ok(header_value) => {
                            req.headers_mut()
                                .insert(http::header::AUTHORIZATION, header_value);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse auth token for header: {e}");
                        }
                    },
                    Ok(None) => {
                        tracing::warn!("No token available for request requiring authentication");
                    }
                    Err(e) => {
                        tracing::warn!("Failed to get auth token: {e}");
                    }
                };
            }
            Some(auth) => {
                tracing::warn!(?auth, "Unsupported authentication method in request");
            }
            None => (),
        }

        next.run(req, ext).await
    }
}
