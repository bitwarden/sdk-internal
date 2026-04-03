use std::sync::Arc;

use bitwarden_auth::token_management::PasswordManagerTokenHandler;
use bitwarden_core::ClientBuilder;

use crate::PasswordManagerClient;

pub struct PasswordManagerClientBuilder {
    settings: Option<bitwarden_core::ClientSettings>,
}

impl PasswordManagerClientBuilder {
    pub fn new() -> Self {
        Self { settings: None }
    }

    pub fn with_settings(mut self, settings: bitwarden_core::ClientSettings) -> Self {
        self.settings = Some(settings);
        self
    }

    pub fn build(self) -> PasswordManagerClient {
        let token_handler = Arc::new(PasswordManagerTokenHandler::default());
        let mut builder = ClientBuilder::new().with_token_handler(token_handler);
        if let Some(s) = self.settings {
            builder = builder.with_settings(s);
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
}
