use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{login::LoginClient, registration::RegistrationClient, send_access::SendAccessClient};

/// Subclient containing auth functionality.
#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct AuthClient {
    // TODO: The AuthClient should probably not contain the whole bitwarden-core client.
    // Instead, it should contain the ApiConfigurations and Tokens struct to do API requests and
    // handle token renewals, and those structs should be shared between core and auth.
    pub(crate) client: Client,
}

impl AuthClient {
    /// Constructs a new `AuthClient` with the given `Client`.
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AuthClient {
    /// Client for login functionality
    pub fn login(&self) -> LoginClient {
        LoginClient::new(self.client.clone())
    }

    /// Client for send access functionality
    pub fn send_access(&self) -> SendAccessClient {
        SendAccessClient::new(self.client.clone())
    }

    /// Client for initializing user account cryptography and unlock methods after JIT provisioning
    pub fn registration(&self) -> RegistrationClient {
        RegistrationClient::new(self.client.clone())
    }
}

/// Extension trait for `Client` to provide access to the `AuthClient`.
pub trait AuthClientExt {
    /// Creates a new `AuthClient` instance.
    fn auth_new(&self) -> AuthClient;
}

impl AuthClientExt for Client {
    fn auth_new(&self) -> AuthClient {
        AuthClient {
            client: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn login_client_shares_the_auth_clients_backing_client() {
        let client = Client::new(None);
        let auth_client = AuthClient::new(client.clone());

        let login_client = auth_client.login();

        assert!(
            Arc::ptr_eq(&client.internal, &login_client.client.internal),
            "LoginClient must reuse the same Client instance backing the AuthClient it came \
             from, otherwise login requests can target a different server than the rest of the \
             SDK"
        );
    }
}
