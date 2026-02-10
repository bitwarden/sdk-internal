//! Token handler implementation for Bitwarden Secrets Manager authentication.

use std::sync::{Arc, RwLock};

use bitwarden_core::{
    NotAuthenticatedError, OrganizationId,
    auth::{TokenHandler, login::LoginError},
    client::login_method::{LoginMethod, ServiceAccountLoginMethod},
    key_management::KeyIds,
};
use bitwarden_crypto::KeyStore;
use chrono::Utc;

use super::common::{MiddlewareExt, MiddlewareWrapper};
use crate::renew::common::TOKEN_RENEW_MARGIN_SECONDS;

/// Token handler for Bitwarden authentication.
#[derive(Clone, Default)]
pub struct SecretsManagerTokenHandler {
    inner: Arc<RwLock<SecretsManagerTokenHandlerInner>>,
}

#[derive(Clone, Default)]
struct SecretsManagerTokenHandlerInner {
    access_token: Option<String>,
    expires_on: Option<i64>,

    // The following are passed as optional as they are filled in when instantiating the
    // middleware.
    login_method: Option<Arc<RwLock<Option<Arc<LoginMethod>>>>>,
    identity_config: Option<bitwarden_api_api::Configuration>,
    key_store: Option<KeyStore<KeyIds>>,
}

impl TokenHandler for SecretsManagerTokenHandler {
    fn initialize_middleware(
        &self,
        login_method: Arc<RwLock<Option<Arc<LoginMethod>>>>,
        identity_config: bitwarden_api_api::Configuration,
        key_store: KeyStore<KeyIds>,
    ) -> Arc<dyn reqwest_middleware::Middleware> {
        {
            let mut inner = self.inner.write().expect("RwLock is not poisoned");
            inner.login_method = Some(login_method);
            inner.identity_config = Some(identity_config);
            inner.key_store = Some(key_store);
        }
        Arc::new(MiddlewareWrapper(self.clone()))
    }

    fn set_tokens(&self, access_token: String, _refresh_token: Option<String>, expires_on: u64) {
        let mut inner = self.inner.write().expect("RwLock is not poisoned");
        inner.access_token = Some(access_token);
        inner.expires_on = Some(expires_on as i64);
    }
}

impl SecretsManagerTokenHandler {
    /// Get the organization ID associated with the current access token, if available.
    pub fn get_access_token_organization(&self) -> Option<OrganizationId> {
        let guard = self.inner.read().ok()?;
        let login_method = guard.login_method.as_ref()?.read().ok()?;

        match login_method.as_ref()?.as_ref() {
            LoginMethod::User(_) => None,
            LoginMethod::ServiceAccount(ServiceAccountLoginMethod::AccessToken {
                organization_id,
                ..
            }) => Some(*organization_id),
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl MiddlewareExt for SecretsManagerTokenHandler {
    async fn get_token(&self) -> Result<Option<String>, LoginError> {
        let inner = self.inner.read().expect("RwLock is not poisoned").clone();

        // Validate the token, returning early if it's still valid.
        if let Some(expires) = inner.expires_on {
            if Utc::now().timestamp() < expires - TOKEN_RENEW_MARGIN_SECONDS {
                return Ok(inner.access_token.clone());
            }
        }

        // These should always be set by initialize_middleware before we get here, but we return an
        // error if not.
        let login_method = inner.login_method.ok_or(NotAuthenticatedError)?;
        let identity_config = inner.identity_config.ok_or(NotAuthenticatedError)?;
        let key_store = inner.key_store.ok_or(NotAuthenticatedError)?;

        let login_method = login_method
            .read()
            .expect("RwLock is not poisoned")
            .clone()
            .ok_or(NotAuthenticatedError)?;

        let LoginMethod::ServiceAccount(service_account_login_method) = login_method.as_ref()
        else {
            return Err(NotAuthenticatedError.into());
        };

        let (access_token, refresh_token, expires_on) =
            bitwarden_core::auth::renew::renew_sm_token_sdk_managed(
                service_account_login_method,
                identity_config,
                key_store,
            )
            .await?;

        self.set_tokens(access_token.clone(), refresh_token, expires_on);
        Ok(Some(access_token))
    }
}
