use bitwarden_vault::{CipherListView, CipherView, EncryptionContext, Fido2CredentialNewView};
use passkey::authenticator::UIHint;
use thiserror::Error;

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum Fido2CallbackError {
    #[error("The operation requires user interaction")]
    UserInterfaceRequired,

    #[error("The operation was cancelled by the user")]
    OperationCancelled,

    #[error("Unknown error: {0}")]
    Unknown(String),
}

#[allow(missing_docs)]
#[async_trait::async_trait]
pub trait Fido2UserInterface: Send + Sync {
    async fn check_user<'a>(
        &self,
        options: CheckUserOptions,
        hint: UIHint<'a, CipherView>,
    ) -> Result<CheckUserResult, Fido2CallbackError>;
    async fn pick_credential_for_authentication(
        &self,
        available_credentials: Vec<CipherView>,
    ) -> Result<CipherView, Fido2CallbackError>;
    async fn check_user_and_pick_credential_for_creation(
        &self,
        options: CheckUserOptions,
        new_credential: Fido2CredentialNewView,
    ) -> Result<(CipherView, CheckUserResult), Fido2CallbackError>;
    async fn is_verification_enabled(&self) -> bool;
}

#[allow(missing_docs)]
#[async_trait::async_trait]
pub trait Fido2CredentialStore: Send + Sync {
    async fn find_credentials(
        &self,
        ids: Option<Vec<Vec<u8>>>,
        rip_id: String,
    ) -> Result<Vec<CipherView>, Fido2CallbackError>;

    async fn all_credentials(&self) -> Result<Vec<CipherListView>, Fido2CallbackError>;

    async fn save_credential(&self, cred: EncryptionContext) -> Result<(), Fido2CallbackError>;
}

#[allow(missing_docs)]
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CheckUserOptions {
    pub require_presence: bool,
    pub require_verification: Verification,
}

#[allow(missing_docs)]
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum Verification {
    Discouraged,
    Preferred,
    Required,
}

#[allow(missing_docs)]
pub struct CheckUserResult {
    pub user_present: bool,
    pub user_verified: bool,
}
