use std::sync::Arc;

use bitwarden_core::{Client, FromClient, client::ApiConfigurations, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;

use crate::{InviteLinkAdminClient, InviteLinkUserClient};

/// Client for organization invite link operations.
///
/// This is a thin entry point that exposes two focused sub-clients: [`InviteLinkAdminClient`] (via
/// [`admin`](Self::admin)) for administrator CRUD operations, and [`InviteLinkUserClient`] (via
/// [`user`](Self::user)) for invitee flows.
#[bitwarden_ffi::wasm_object]
#[derive(FromClient)]
pub struct InviteLinkClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[bitwarden_ffi::wasm_export]
impl InviteLinkClient {
    /// Administrative (organization-key) invite link operations.
    pub fn admin(&self) -> InviteLinkAdminClient {
        InviteLinkAdminClient {
            key_store: self.key_store.clone(),
            api_configurations: self.api_configurations.clone(),
        }
    }

    /// Invitee (user) invite link operations.
    pub fn user(&self) -> InviteLinkUserClient {
        InviteLinkUserClient {
            key_store: self.key_store.clone(),
            api_configurations: self.api_configurations.clone(),
        }
    }
}

/// Extension trait that exposes [`InviteLinkClient`] on [`Client`].
pub trait InviteLinkClientExt {
    /// Returns an [`InviteLinkClient`]
    fn invite_link(&self) -> InviteLinkClient;
}

impl InviteLinkClientExt for Client {
    fn invite_link(&self) -> InviteLinkClient {
        InviteLinkClient::from_client(self)
    }
}
