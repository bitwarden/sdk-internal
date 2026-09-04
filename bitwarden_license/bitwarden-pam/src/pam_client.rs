use std::sync::Arc;

use bitwarden_core::{Client, FromClient, client::ApiConfigurations};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    access_requests::AccessRequestsClient, access_rules::AccessRulesClient, leases::LeasesClient,
};

/// Entry point for Privileged Access Management (PAM) operations.
#[derive(Clone, FromClient)]
#[bitwarden_ffi::wasm_object]
pub struct PamClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[bitwarden_ffi::wasm_export]
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

    /// Access lease operations (read, extend, and end the caller's leases).
    pub fn leases(&self) -> LeasesClient {
        LeasesClient {
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
