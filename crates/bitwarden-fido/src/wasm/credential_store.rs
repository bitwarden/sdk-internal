use bitwarden_threading::ThreadBoundRunner;
use bitwarden_vault::{CipherListView, CipherView, EncryptionContext};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

use super::{from_js, js_error, to_js};
use crate::{Fido2CallbackError, Fido2CredentialStore};

#[wasm_bindgen(typescript_custom_section)]
const CREDENTIAL_STORE_CUSTOM_TS_TYPE: &'static str = r#"
export interface Fido2CredentialStore {
    // Byte arrays cross as `number[]`, not `Uint8Array`: `serde_wasm_bindgen` only emits a
    // `Uint8Array` for `serialize_bytes`, and these are plain `Vec<u8>`.
    find_credentials(ids: number[][] | undefined, rip_id: string, user_handle: number[] | undefined): Promise<CipherView[]>;
    all_credentials(): Promise<CipherListView[]>;
    save_credential(cred: EncryptionContext): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// JavaScript implementation of the credential store consulted during a FIDO2 ceremony.
    #[wasm_bindgen(js_name = Fido2CredentialStore, typescript_type = "Fido2CredentialStore")]
    pub type RawJsFido2CredentialStore;

    /// `rip_id` is misspelled to match [Fido2CredentialStore::find_credentials]. Renaming it here
    /// would silently stop matching the JavaScript object.
    #[wasm_bindgen(method, catch)]
    async fn find_credentials(
        this: &RawJsFido2CredentialStore,
        ids: JsValue,
        rip_id: String,
        user_handle: JsValue,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn all_credentials(this: &RawJsFido2CredentialStore) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn save_credential(
        this: &RawJsFido2CredentialStore,
        cred: JsValue,
    ) -> Result<(), JsValue>;
}

/// Adapts a JavaScript credential store to the [Fido2CredentialStore] trait.
pub(super) struct JsFido2CredentialStore {
    runner: ThreadBoundRunner<RawJsFido2CredentialStore>,
}

impl JsFido2CredentialStore {
    pub(super) fn new(store: RawJsFido2CredentialStore) -> Self {
        Self {
            runner: ThreadBoundRunner::new(store),
        }
    }
}

#[async_trait::async_trait]
impl Fido2CredentialStore for JsFido2CredentialStore {
    async fn find_credentials(
        &self,
        ids: Option<Vec<Vec<u8>>>,
        rip_id: String,
        user_handle: Option<Vec<u8>>,
    ) -> Result<Vec<CipherView>, Fido2CallbackError> {
        self.runner
            .run_in_thread(move |store| async move {
                let credentials = store
                    .find_credentials(to_js(&ids)?, rip_id, to_js(&user_handle)?)
                    .await
                    .map_err(js_error)?;
                from_js(credentials)
            })
            .await?
    }

    async fn all_credentials(&self) -> Result<Vec<CipherListView>, Fido2CallbackError> {
        self.runner
            .run_in_thread(|store| async move {
                let credentials = store.all_credentials().await.map_err(js_error)?;
                from_js(credentials)
            })
            .await?
    }

    async fn save_credential(&self, cred: EncryptionContext) -> Result<(), Fido2CallbackError> {
        self.runner
            .run_in_thread(move |store| async move {
                store.save_credential(to_js(&cred)?).await.map_err(js_error)
            })
            .await?
    }
}
