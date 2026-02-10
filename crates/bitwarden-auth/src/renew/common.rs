//! Shared utilities for token renewal.

use bitwarden_api_api::apis::AuthRequired;
use bitwarden_core::auth::login::LoginError;

pub(crate) const TOKEN_RENEW_MARGIN_SECONDS: i64 = 5 * 60;

pub(crate) struct MiddlewareWrapper<T>(pub(crate) T);

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub(crate) trait MiddlewareExt: 'static + Send + Sync {
    async fn get_token(&self) -> Result<Option<String>, LoginError>;
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl<T: MiddlewareExt> reqwest_middleware::Middleware for MiddlewareWrapper<T> {
    async fn handle(
        &self,
        mut req: reqwest::Request,
        ext: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> Result<reqwest::Response, reqwest_middleware::Error> {
        if ext.get::<AuthRequired>().is_some() {
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

        next.run(req, ext).await
    }
}
