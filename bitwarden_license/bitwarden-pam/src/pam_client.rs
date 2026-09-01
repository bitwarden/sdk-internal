use std::sync::Arc;

use bitwarden_core::{Client, FromClient, client::ApiConfigurations, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    access_requests::AccessRequestsClient, access_rules::AccessRulesClient,
    approvals::ApprovalsClient, leases::LeasesClient,
};

/// Entry point for Privileged Access Management (PAM) operations.
#[derive(Clone, FromClient)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct PamClient {
    /// Only [`LeasesClient`] needs this: reading the cipher a lease unlocks is the one PAM call
    /// that decrypts a vault payload rather than a leasing one.
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl PamClient {
    /// Access rule CRUD operations.
    pub fn access_rules(&self) -> AccessRulesClient {
        AccessRulesClient {
            api_configurations: self.api_configurations.clone(),
        }
    }

    /// Access request operations (activate, cancel, and read the caller's requests).
    pub fn access_requests(&self) -> AccessRequestsClient {
        AccessRequestsClient {
            api_configurations: self.api_configurations.clone(),
        }
    }

    /// Approver-side access request operations (inbox, history, and recording a decision).
    pub fn approvals(&self) -> ApprovalsClient {
        ApprovalsClient {
            api_configurations: self.api_configurations.clone(),
        }
    }

    /// Access lease operations (read, extend, and end the caller's leases).
    pub fn leases(&self) -> LeasesClient {
        LeasesClient {
            key_store: self.key_store.clone(),
            api_configurations: self.api_configurations.clone(),
        }
    }
}

/// Extension trait that exposes [`PamClient`] on [`Client`].
pub trait PamClientExt {
    /// Returns a [`PamClient`] backed by this client.
    fn pam(&self) -> PamClient;
}

impl PamClientExt for Client {
    fn pam(&self) -> PamClient {
        PamClient::from_client(self)
    }
}
