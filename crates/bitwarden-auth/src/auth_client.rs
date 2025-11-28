use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    identity::IdentityClient, send_access::SendAccessClient,
    user_registration::UserRegistrationClient,
};

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
    /// Client for identity functionality
    pub fn identity(&self) -> IdentityClient {
        IdentityClient::new(self.client.clone())
    }

    /// Client for send access functionality
    pub fn send_access(&self) -> SendAccessClient {
        SendAccessClient::new(self.client.clone())
    }

    /// Client for initializing user account cryptography and unlock methods after JIT provisioning
    pub fn user_registration(&self) -> UserRegistrationClient {
        UserRegistrationClient::new(self.client.clone())
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
