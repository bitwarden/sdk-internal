use bitwarden_threading::ThreadBoundRunner;
use bitwarden_vault::{CipherView, Fido2CredentialNewView};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

use super::{from_js, js_error, to_js};
use crate::{
    CheckUserOptions, CheckUserResult, Fido2CallbackError, Fido2UserInterface,
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, UiHint,
};

/// Owned mirror of [UiHint].
///
/// [UiHint] is generic, borrows its payload, and is defined upstream in `passkey`, so it cannot
/// cross the boundary as-is. The borrowed cipher is cloned into this type before the callback.
#[derive(Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum Fido2UiHint {
    /// The relying party excluded a credential the vault already holds, so registration cannot
    /// continue.
    InformExcludedCredentialFound(CipherView),
    /// No credential in the vault can satisfy the request.
    InformNoCredentialsFound,
    /// Registration needs a cipher to store the new credential in.
    RequestNewCredential {
        /// The account the relying party is registering.
        user: PublicKeyCredentialUserEntity,
        /// The relying party requesting registration.
        rp: PublicKeyCredentialRpEntity,
    },
    /// Authentication needs the user to confirm the credential to assert with.
    RequestExistingCredential(CipherView),
}

impl From<UiHint<'_, CipherView>> for Fido2UiHint {
    fn from(hint: UiHint<'_, CipherView>) -> Self {
        match hint {
            UiHint::InformExcludedCredentialFound(cipher) => {
                Fido2UiHint::InformExcludedCredentialFound(cipher.clone())
            }
            UiHint::InformNoCredentialsFound => Fido2UiHint::InformNoCredentialsFound,
            UiHint::RequestNewCredential(user, rp) => Fido2UiHint::RequestNewCredential {
                user: PublicKeyCredentialUserEntity {
                    id: user.id.clone().into(),
                    name: user.name.clone().unwrap_or_default(),
                    display_name: user.display_name.clone().unwrap_or_default(),
                },
                rp: PublicKeyCredentialRpEntity {
                    id: rp.id.clone(),
                    name: rp.name.clone(),
                },
            },
            UiHint::RequestExistingCredential(cipher) => {
                Fido2UiHint::RequestExistingCredential(cipher.clone())
            }
        }
    }
}

/// Result of [Fido2UserInterface::check_user_and_pick_credential_for_creation].
///
/// The trait returns a tuple, which serializes as a positional array. A named struct is used here
/// so the TypeScript contract stays readable.
#[derive(Serialize, Deserialize, Tsify)]
#[serde(rename_all = "camelCase")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct CheckUserAndPickCredentialForCreationResult {
    /// The cipher the new credential will be stored in.
    pub cipher: CipherView,
    /// The outcome of the user check performed while picking it.
    pub check_user_result: CheckUserResult,
}

#[wasm_bindgen(typescript_custom_section)]
const USER_INTERFACE_CUSTOM_TS_TYPE: &'static str = r#"
export interface Fido2UserInterface {
    check_user(options: CheckUserOptions, hint: Fido2UiHint): Promise<CheckUserResult>;
    pick_credential_for_authentication(available_credentials: CipherView[]): Promise<CipherView>;
    check_user_and_pick_credential_for_creation(options: CheckUserOptions, new_credential: Fido2CredentialNewView): Promise<CheckUserAndPickCredentialForCreationResult>;
    // Read once, when the authenticator is built. Later changes are not observed, so this is a
    // property rather than a method.
    readonly is_verification_enabled: boolean;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// JavaScript implementation of the user interface driven during a FIDO2 ceremony.
    #[wasm_bindgen(js_name = Fido2UserInterface, typescript_type = "Fido2UserInterface")]
    pub type RawJsFido2UserInterface;

    #[wasm_bindgen(method, catch)]
    async fn check_user(
        this: &RawJsFido2UserInterface,
        options: JsValue,
        hint: JsValue,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn pick_credential_for_authentication(
        this: &RawJsFido2UserInterface,
        available_credentials: JsValue,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn check_user_and_pick_credential_for_creation(
        this: &RawJsFido2UserInterface,
        options: JsValue,
        new_credential: JsValue,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, getter, catch)]
    fn is_verification_enabled(this: &RawJsFido2UserInterface) -> Result<bool, JsValue>;
}

/// Adapts a JavaScript user interface to the [Fido2UserInterface] trait.
pub(super) struct JsFido2UserInterface {
    runner: ThreadBoundRunner<RawJsFido2UserInterface>,
    verification_enabled: bool,
}

impl JsFido2UserInterface {
    pub(super) fn new(user_interface: RawJsFido2UserInterface) -> Self {
        // `is_verification_enabled` is synchronous on the trait, but once the JavaScript object is
        // handed to the runner it can only be reached through an async call. Read it here, while
        // still on the thread that constructed it, and answer from the cached value afterwards.
        // A throwing implementation degrades to "not enabled", which weakens the ceremony, so it is
        // logged rather than swallowed.
        let verification_enabled = match user_interface.is_verification_enabled() {
            Ok(enabled) => enabled,
            Err(error) => {
                tracing::error!(
                    ?error,
                    "is_verification_enabled threw; treating verification as disabled"
                );
                false
            }
        };

        Self {
            runner: ThreadBoundRunner::new(user_interface),
            verification_enabled,
        }
    }
}

#[async_trait::async_trait]
impl Fido2UserInterface for JsFido2UserInterface {
    async fn check_user<'a>(
        &self,
        options: CheckUserOptions,
        hint: UiHint<'a, CipherView>,
    ) -> Result<CheckUserResult, Fido2CallbackError> {
        let hint = Fido2UiHint::from(hint);

        self.runner
            .run_in_thread(move |ui| async move {
                let result = ui
                    .check_user(to_js(&options)?, to_js(&hint)?)
                    .await
                    .map_err(js_error)?;
                from_js(result)
            })
            .await?
    }

    async fn pick_credential_for_authentication(
        &self,
        available_credentials: Vec<CipherView>,
    ) -> Result<CipherView, Fido2CallbackError> {
        self.runner
            .run_in_thread(move |ui| async move {
                let credential = ui
                    .pick_credential_for_authentication(to_js(&available_credentials)?)
                    .await
                    .map_err(js_error)?;
                from_js(credential)
            })
            .await?
    }

    async fn check_user_and_pick_credential_for_creation(
        &self,
        options: CheckUserOptions,
        new_credential: Fido2CredentialNewView,
    ) -> Result<(CipherView, CheckUserResult), Fido2CallbackError> {
        self.runner
            .run_in_thread(move |ui| async move {
                let result = ui
                    .check_user_and_pick_credential_for_creation(
                        to_js(&options)?,
                        to_js(&new_credential)?,
                    )
                    .await
                    .map_err(js_error)?;
                let result: CheckUserAndPickCredentialForCreationResult = from_js(result)?;
                Ok((result.cipher, result.check_user_result))
            })
            .await?
    }

    fn is_verification_enabled(&self) -> bool {
        self.verification_enabled
    }
}
