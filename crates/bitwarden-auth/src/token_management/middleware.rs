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
    /// Retrieves the current access token, renewing it if necessary. If `force` is true,
    /// the token should be renewed regardless of its current expiration time.
    async fn get_token(&self, force: bool) -> Result<Option<String>, LoginError>;
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
        let required_auth = self.inject_token_if_required(&mut req, ext, false).await;

        let req_clone = req.try_clone();
        let result = next.clone().run(req, ext).await?;

        // If the request required auth and got a 401 Unauthorized response, the token might have
        // been invalidated. In that case, we should try to refresh it and retry the request.
        if required_auth
            && let Some(mut req_clone) = req_clone
            && result.status() == http::StatusCode::UNAUTHORIZED
        {
            tracing::info!("Received 401 response, attempting token refresh and retrying");
            self.inject_token_if_required(&mut req_clone, ext, true)
                .await;
            return next.run(req_clone, ext).await;
        }

        Ok(result)
    }
}

impl<T: MiddlewareExt> MiddlewareWrapper<T> {
    /// Attaches an authentication header to `req` based on the [AuthRequired] extension, if any.
    /// Returns `true` when the request specified an authentication method (regardless of whether
    /// a token was successfully retrieved and attached) so callers can decide whether to retry on
    /// auth failures.
    async fn inject_token_if_required(
        &self,
        req: &mut reqwest::Request,
        ext: &http::Extensions,
        force: bool,
    ) -> bool {
        match ext.get::<AuthRequired>() {
            Some(AuthRequired::Bearer) => {
                match self.0.get_token(force).await {
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

                return true;
            }
            Some(auth) => {
                tracing::warn!(?auth, "Unsupported authentication method in request");
            }
            None => (),
        }
        false
    }
}
