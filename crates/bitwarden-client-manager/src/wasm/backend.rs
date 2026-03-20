use bitwarden_core::{Client, UserId};
use bitwarden_threading::ThreadBoundRunner;
use wasm_bindgen::{convert::TryFromJsValue, prelude::*};

use crate::backend::{ClientHasNoUserIdError, ClientManagerBackend};

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export interface ClientManagerBackend {
    get_client(userId: UserId): Promise<Client | undefined>;
    set_client(client: Client): Promise<void>;
    delete_client(userId: UserId): Promise<void>;

    get_active_client(): Promise<Client | undefined>;
    set_active_client(userId: UserId): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// JavaScript interface for managing client storage.
    #[wasm_bindgen(js_name = ClientManagerBackend, typescript_type = "ClientManagerBackend")]
    pub type RawJsClientManagerBackend;

    /// Used by the SDK to get a client for a specific user ID.
    #[wasm_bindgen(catch, method, structural)]
    pub async fn get_client(
        this: &RawJsClientManagerBackend,
        user_id: UserId,
    ) -> Result<JsValue, JsValue>;

    /// Used by the SDK to save a client for a specific user ID.
    #[wasm_bindgen(catch, method, structural)]
    pub async fn set_client(
        this: &RawJsClientManagerBackend,
        client: Client,
    ) -> Result<(), JsValue>;

    /// Used by the SDK to remove a client for a specific user ID.
    #[wasm_bindgen(catch, method, structural)]
    pub async fn delete_client(
        this: &RawJsClientManagerBackend,
        user_id: UserId,
    ) -> Result<(), JsValue>;

    /// Used by the SDK to get the active client.
    #[wasm_bindgen(catch, method, structural)]
    pub async fn get_active_client(this: &RawJsClientManagerBackend) -> Result<JsValue, JsValue>;

    /// Used by the SDK to set the active client by user ID.
    #[wasm_bindgen(catch, method, structural)]
    pub async fn set_active_client(
        this: &RawJsClientManagerBackend,
        user_id: UserId,
    ) -> Result<(), JsValue>;
}

/// Thread-safe JavaScript implementation of the `ClientManagerBackend` trait.
pub struct JsClientManagerBackend(ThreadBoundRunner<RawJsClientManagerBackend>);

impl JsClientManagerBackend {
    pub fn new(backend: RawJsClientManagerBackend) -> Self {
        Self(ThreadBoundRunner::new(backend))
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl ClientManagerBackend for JsClientManagerBackend {
    async fn get_client(&self, user_id: &UserId) -> Option<Client> {
        let user_id = *user_id;
        self.0
            .run_in_thread(move |backend| async move {
                let js_value = backend.get_client(user_id).await.ok()?;
                Client::try_from_js_value(js_value).ok()
            })
            .await
            .ok()
            .flatten()
    }

    async fn set_client(&self, client: Client) -> Result<(), ClientHasNoUserIdError> {
        client
            .internal
            .get_user_id()
            .ok_or(ClientHasNoUserIdError)?;
        let _ = self
            .0
            .run_in_thread(move |backend| async move { backend.set_client(client).await })
            .await;
        Ok(())
    }

    async fn delete_client(&self, user_id: &UserId) {
        let user_id = *user_id;
        let _ = self
            .0
            .run_in_thread(move |backend| async move { backend.delete_client(user_id).await })
            .await;
    }

    async fn get_active_client(&self) -> Option<Client> {
        self.0
            .run_in_thread(move |backend| async move {
                let js_value = backend.get_active_client().await.ok()?;
                Client::try_from_js_value(js_value).ok()
            })
            .await
            .ok()
            .flatten()
    }

    async fn set_active_client(&self, user_id: &UserId) {
        let user_id = *user_id;
        let _ = self
            .0
            .run_in_thread(move |backend| async move { backend.set_active_client(user_id).await })
            .await;
    }
}
