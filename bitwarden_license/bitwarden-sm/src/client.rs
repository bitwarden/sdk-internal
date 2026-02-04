//! Client for the Bitwarden Secrets Manager API

use std::sync::Arc;

pub use bitwarden_core::ClientSettings;
use bitwarden_core::{OrganizationId, auth::auth_client::AuthClient};
use bitwarden_generators::GeneratorClientsExt;

use crate::{ProjectsClient, SecretsClient};

/// The main struct for interacting with the Secrets Manager service through the SM SDK.
pub struct SecretsManagerClient {
    client: bitwarden_core::Client,
}

impl SecretsManagerClient {
    /// Create a new SecretsManagerClient
    pub fn new(settings: Option<ClientSettings>) -> Self {
        let token_handler = Arc::new(bitwarden_auth::renew::AuthTokenHandler::default());
        Self {
            client: bitwarden_core::Client::new_with_token_handler(settings, token_handler),
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
        self.client.internal.get_access_token_organization()
    }
}
