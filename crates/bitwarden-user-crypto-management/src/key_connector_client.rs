use std::sync::Arc;

use bitwarden_core::{Client, FromClient, client::ApiConfigurations, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct KeyConnectorClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

pub trait KeyConnectorClientExt {
    fn key_connector(&self) -> KeyConnectorClient;
}

impl KeyConnectorClientExt for Client {
    fn key_connector(&self) -> KeyConnectorClient {
        KeyConnectorClient::from_client(self)
    }
}
