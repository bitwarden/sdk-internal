use bitwarden_core::{Client, FromClient};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Entry point for Privileged Access Management (PAM) operations.
#[derive(Clone, FromClient)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct PamClient {}

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
