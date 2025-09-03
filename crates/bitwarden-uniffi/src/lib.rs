#![doc = include_str!("../README.md")]

uniffi::setup_scaffolding!();

use auth::AuthClient;
use bitwarden_core::{auth::AuthValidateError, ClientSettings, WrongPasswordError};

#[allow(missing_docs)]
pub mod auth;
#[allow(missing_docs)]
pub mod crypto;
mod error;
#[allow(missing_docs)]
pub mod platform;
#[allow(missing_docs)]
pub mod tool;
mod uniffi_support;
#[allow(missing_docs)]
pub mod vault;

#[cfg(target_os = "android")]
mod android_support;

use bitwarden_exporters::ExporterClientExt;
use bitwarden_generators::GeneratorClientsExt;
use bitwarden_send::SendClientExt;
use bitwarden_vault::VaultClientExt;
use crypto::CryptoClient;
use error::{Error, Result};
use platform::PlatformClient;
use tool::{ExporterClient, GeneratorClients, SendClient, SshClient};
use vault::VaultClient;

#[allow(missing_docs)]
#[derive(uniffi::Object)]
pub struct Client(pub(crate) bitwarden_core::Client);

#[uniffi::export(async_runtime = "tokio")]
impl Client {
    /// Initialize a new instance of the SDK client
    #[uniffi::constructor]
    pub fn new(settings: Option<ClientSettings>) -> Self {
        init_logger();
        setup_error_converter();

        #[cfg(target_os = "android")]
        android_support::init();

        Self(bitwarden_core::Client::new(settings))
    }

    /// Crypto operations
    pub fn crypto(&self) -> CryptoClient {
        CryptoClient(self.0.crypto())
    }

    /// Vault item operations
    pub fn vault(&self) -> VaultClient {
        VaultClient(self.0.vault())
    }

    #[allow(missing_docs)]
    pub fn platform(&self) -> PlatformClient {
        PlatformClient(self.0.clone())
    }

    /// Generator operations
    pub fn generators(&self) -> GeneratorClients {
        GeneratorClients(self.0.generator())
    }

    /// Exporters
    pub fn exporters(&self) -> ExporterClient {
        ExporterClient(self.0.exporters())
    }

    /// Sends operations
    pub fn sends(&self) -> SendClient {
        SendClient(self.0.sends())
    }

    /// SSH operations
    pub fn ssh(&self) -> SshClient {
        SshClient()
    }

    /// Auth operations
    pub fn auth(&self) -> AuthClient {
        AuthClient(self.0.clone())
    }

    /// Test method, echoes back the input
    pub fn echo(&self, msg: String) -> String {
        msg
    }

    /// Test method, calls http endpoint
    pub async fn http_get(&self, url: String) -> Result<String> {
        let client = self.0.internal.get_http_client();
        let res = client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Api(e.into()))?;

        res.text().await.map_err(|e| Error::Api(e.into()))
    }
}

fn init_logger() {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    #[cfg(target_os = "ios")]
    let _ = oslog::OsLogger::new("com.8bit.bitwarden")
        .level_filter(log::LevelFilter::Info)
        .init();

    #[cfg(target_os = "android")]
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("com.bitwarden.sdk")
            .with_max_level(log::LevelFilter::Info),
    );
}

/// Setup the error converter to ensure conversion errors don't cause panics
/// Check [`bitwarden_uniffi_error`] for more details
fn setup_error_converter() {
    bitwarden_uniffi_error::set_error_to_uniffi_error(|e| {
        crate::error::BitwardenError::ConversionError(e.to_string()).into()
    });
}

mod workarounds {
    use bitwarden_core::{
        auth::{auth_client::*, *},
        client::encryption_settings::*,
        key_management::crypto::*,
        platform::*,
        ApiError,
    };
    use bitwarden_crypto::*;
    use bitwarden_exporters::*;
    use bitwarden_fido::*;
    use bitwarden_generators::*;
    use bitwarden_send::*;
    use bitwarden_ssh::error::*;
    use bitwarden_vault::*;

    #[derive(uniffi::Object)]
    pub struct WorkaroundsDoNotUse {}

    #[uniffi::export]
    impl WorkaroundsDoNotUse {
        pub fn api(&self) -> Result<(), ApiError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn approve_auth_request(&self) -> Result<(), ApproveAuthRequestError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn auth_validate(&self) -> Result<(), AuthValidateError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn cipher(&self) -> Result<(), CipherError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn credentials_for_autofill(&self) -> Result<(), CredentialsForAutofillError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn crypto_client(&self) -> Result<(), CryptoClientError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn crypto(&self) -> Result<(), CryptoError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn decrypt(&self) -> Result<(), DecryptError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn decrypt_fido2_autofill_credentials(
            &self,
        ) -> Result<(), DecryptFido2AutofillCredentialsError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn decrypt_file(&self) -> Result<(), DecryptFileError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn derive_key_connector(&self) -> Result<(), DeriveKeyConnectorError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn encrypt(&self) -> Result<(), EncryptError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn encrypt_file(&self) -> Result<(), EncryptFileError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn encryption_settings(&self) -> Result<(), EncryptionSettingsError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn enroll_admin_password_reset(&self) -> Result<(), EnrollAdminPasswordResetError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn export(&self) -> Result<(), ExportError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn fido2_client(&self) -> Result<(), Fido2ClientError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn fingerprint(&self) -> Result<(), FingerprintError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn get_assertion(&self) -> Result<(), GetAssertionError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn key_generation(&self) -> Result<(), KeyGenerationError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn make_credential(&self) -> Result<(), MakeCredentialError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn passphrase(&self) -> Result<(), PassphraseError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn password(&self) -> Result<(), PasswordError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn send_decrypt(&self) -> Result<(), SendDecryptError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn send_decrypt_file(&self) -> Result<(), SendDecryptFileError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn send_encrypt(&self) -> Result<(), SendEncryptError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn send_encrypt_file(&self) -> Result<(), SendEncryptFileError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn silently_discover_credentials(
            &self,
        ) -> Result<(), SilentlyDiscoverCredentialsError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn ssh_key_import(&self) -> Result<(), SshKeyImportError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn totp(&self) -> Result<(), TotpError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn trust_device(&self) -> Result<(), TrustDeviceError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn user_fingerprint(&self) -> Result<(), UserFingerprintError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }

        pub fn username(&self) -> Result<(), UsernameError> {
            panic!("Do not use this function, it is only here to work around a uniffi limitation");
        }
    }
}
