use std::sync::Arc;

use bitwarden_auth::token_management::PasswordManagerTokenHandler;
use bitwarden_core::ClientBuilder;

use crate::PasswordManagerClient;

/// Builder for constructing [`PasswordManagerClient`] instances with custom configuration.
pub struct PasswordManagerClientBuilder {
    settings: Option<bitwarden_core::ClientSettings>,
    cookie_provider:
        Option<std::sync::Arc<dyn bitwarden_server_communication_config::CookieProvider>>,
}

impl PasswordManagerClientBuilder {
    /// Creates a new [`PasswordManagerClientBuilder`] with default settings.
    pub fn new() -> Self {
        Self {
            settings: None,
            cookie_provider: None,
        }
    }

    /// Sets the [`ClientSettings`](bitwarden_core::ClientSettings) for the client being built.
    pub fn with_settings(mut self, settings: bitwarden_core::ClientSettings) -> Self {
        self.settings = Some(settings);
        self
    }

    /// Sets an SSO load balancer cookie provider, enabling cookie middleware for
    /// self-hosted deployments behind sticky-session load balancers.
    pub fn with_server_communication_config(
        mut self,
        cookie_provider: std::sync::Arc<dyn bitwarden_server_communication_config::CookieProvider>,
    ) -> Self {
        self.cookie_provider = Some(cookie_provider);
        self
    }

    /// Consumes the builder and constructs a [`PasswordManagerClient`].
    pub fn build(self) -> PasswordManagerClient {
        let token_handler = Arc::new(PasswordManagerTokenHandler::default());
        let mut builder = ClientBuilder::new().with_token_handler(token_handler);
        if let Some(s) = self.settings {
            builder = builder.with_settings(s);
        }
        if let Some(cookie_provider) = self.cookie_provider {
            let cookie_middleware: Arc<dyn reqwest_middleware::Middleware> = Arc::new(
                bitwarden_server_communication_config::ServerCommunicationConfigMiddleware::new(
                    cookie_provider,
                ),
            );
            builder = builder.with_middleware(vec![cookie_middleware]);
        }
        PasswordManagerClient(builder.build())
    }
}

impl Default for PasswordManagerClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pm_builder_default_builds() {
        let _client = PasswordManagerClientBuilder::new().build();
    }

    #[test]
    fn test_pm_builder_with_settings_builds() {
        let settings = bitwarden_core::ClientSettings::default();
        let _client = PasswordManagerClientBuilder::new()
            .with_settings(settings)
            .build();
    }

    #[test]
    fn test_pm_builder_with_server_communication_config_builds() {
        struct MockCookieProvider;

        #[async_trait::async_trait]
        impl bitwarden_server_communication_config::CookieProvider for MockCookieProvider {
            async fn cookies(&self, _hostname: &str) -> Vec<(String, String)> {
                vec![]
            }

            async fn acquire_cookie(
                &self,
                _hostname: &str,
            ) -> Result<(), bitwarden_server_communication_config::AcquireCookieError> {
                Ok(())
            }

            async fn needs_bootstrap(&self, _hostname: &str) -> bool {
                false
            }
        }

        let _client = PasswordManagerClientBuilder::new()
            .with_server_communication_config(Arc::new(MockCookieProvider))
            .build();
    }
}
