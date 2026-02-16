//! Client for the Bitwarden Secrets Manager API

use std::sync::Arc;

use bitwarden_auth::token_management::SecretsManagerTokenHandler;
pub use bitwarden_core::ClientSettings;
use bitwarden_core::{OrganizationId, auth::auth_client::AuthClient};
use bitwarden_generators::GeneratorClientsExt;

use crate::{ProjectsClient, SecretsClient};

/// The main struct for interacting with the Secrets Manager service through the SM SDK.
pub struct SecretsManagerClient {
    client: bitwarden_core::Client,
    token_handler: Arc<SecretsManagerTokenHandler>,
}

impl SecretsManagerClient {
    /// Create a new SecretsManagerClient
    pub fn new(settings: Option<ClientSettings>) -> Self {
        let token_handler = Arc::new(SecretsManagerTokenHandler::default());
        Self {
            client: bitwarden_core::Client::new_with_token_handler(settings, token_handler.clone()),
            token_handler,
        }
    }

    /// Get access to the Projects API
    pub fn projects(&self) -> ProjectsClient {
        ProjectsClient::new(self.client.clone())
    }

    /// Get access to the Secrets API
    pub fn secrets(&self) -> SecretsClient {
        SecretsClient::new(self.client.clone())
    }

    /// Get access to the Auth API
    pub fn auth(&self) -> AuthClient {
        self.client.auth()
    }

    /// Get access to the Generators API
    pub fn generator(&self) -> bitwarden_generators::GeneratorClient {
        self.client.generator()
    }

    #[doc(hidden)]
    pub fn get_access_token_organization(&self) -> Option<OrganizationId> {
        self.token_handler.get_access_token_organization()
    }
}
