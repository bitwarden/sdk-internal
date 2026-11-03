use std::sync::Arc;

use bitwarden_collections::collection::Collection;
use bitwarden_exporters::{Account, ExportFormat};
use bitwarden_generators::{
    PassphraseGeneratorRequest, PasswordGeneratorRequest, UsernameGeneratorRequest,
};
use bitwarden_importers::{
    Credentials, ImportOptions, ImportSummary, OnePasswordImportSummary, OnePasswordTotpResult,
    OnePasswordTwoFactorUi,
};
use bitwarden_vault::{Cipher, EncryptionContext, Folder};

use crate::error::Result;

mod sends;
pub use sends::SendClient;

mod ssh;
pub use ssh::SshClient;

#[derive(uniffi::Object)]
pub struct GeneratorClients(pub(crate) bitwarden_generators::GeneratorClient);

#[uniffi::export(async_runtime = "tokio")]
impl GeneratorClients {
    /// Generate Password
    pub fn password(&self, settings: PasswordGeneratorRequest) -> Result<String> {
        Ok(self.0.password(settings)?)
    }

    /// Generate Passphrase
    pub fn passphrase(&self, settings: PassphraseGeneratorRequest) -> Result<String> {
        Ok(self.0.passphrase(settings)?)
    }

    /// Parses an HTML `passwordrules` attribute string into a [`PasswordGeneratorRequest`].
    pub fn password_rules(&self, rules: String) -> Result<PasswordGeneratorRequest> {
        Ok(self.0.password_rules(rules)?)
    }

    /// Generate Username
    pub async fn username(&self, settings: UsernameGeneratorRequest) -> Result<String> {
        Ok(self.0.username(settings).await?)
    }
}

#[derive(uniffi::Object)]
pub struct ExporterClient(pub(crate) bitwarden_exporters::ExporterClient);

#[uniffi::export(async_runtime = "tokio")]
impl ExporterClient {
    /// Export user vault
    pub async fn export_vault(
        &self,
        folders: Vec<Folder>,
        ciphers: Vec<Cipher>,
        format: ExportFormat,
    ) -> Result<String> {
        Ok(self.0.export_vault(folders, ciphers, format).await?)
    }

    /// Export organization vault
    pub fn export_organization_vault(
        &self,
        collections: Vec<Collection>,
        ciphers: Vec<Cipher>,
        format: ExportFormat,
    ) -> Result<String> {
        Ok(self
            .0
            .export_organization_vault(collections, ciphers, format)?)
    }

    /// Credential Exchange Format (CXF)
    ///
    /// *Warning:* Expect this API to be unstable, and it will change in the future.
    ///
    /// For use with Apple using [ASCredentialExportManager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager).
    /// Ideally the output should be immediately deserialized to [ASImportableAccount](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
    pub fn export_cxf(&self, account: Account, ciphers: Vec<Cipher>) -> Result<String> {
        Ok(self.0.export_cxf(account, ciphers)?)
    }

    /// Credential Exchange Format (CXF)
    ///
    /// *Warning:* Expect this API to be unstable, and it will change in the future.
    ///
    /// For use with Apple using [ASCredentialExportManager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager).
    /// Ideally the input should be immediately serialized from [ASImportableAccount](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
    pub fn import_cxf(&self, payload: String) -> Result<Vec<EncryptionContext>> {
        Ok(self.0.import_cxf(payload)?)
    }
}

#[derive(uniffi::Object)]
pub struct ImporterClient(pub(crate) bitwarden_importers::ImporterClient);

#[uniffi::export(async_runtime = "tokio")]
impl ImporterClient {
    /// Import a KeePass KDBX (`.kdbx`) database and submit it to the server.
    pub async fn import_kdbx(
        &self,
        file: Vec<u8>,
        password: Option<String>,
        key_file: Option<Vec<u8>>,
        options: ImportOptions,
    ) -> Result<ImportSummary> {
        Ok(self
            .0
            .import_kdbx(file, password, key_file, options)
            .await?)
    }

    /// Import a 1Password account directly from the 1Password servers.
    ///
    /// Signs in, asks `two_factor` for a code when the account requires one, downloads every vault
    /// the account can open, and submits the result. Each vault becomes a folder; the result also
    /// reports vaults and items that could not be imported.
    pub async fn import_onepassword(
        &self,
        credentials: Credentials,
        two_factor: Arc<dyn OnePasswordTwoFactorPrompt>,
        options: ImportOptions,
    ) -> Result<OnePasswordImportSummary> {
        Ok(self
            .0
            .import_onepassword(credentials, &TwoFactorPromptBridge(two_factor), options)
            .await?)
    }
}

/// Asks the user for a 1Password two-factor code.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait OnePasswordTwoFactorPrompt: Send + Sync {
    /// Returns the code the user entered, or `None` if they cancelled. Each rejected code restarts
    /// the login, so `attempt` grows as the user retries.
    async fn provide_totp(&self, attempt: u32) -> Result<Option<String>>;
}

/// Adapts the foreign prompt to the importer's trait, which uniffi cannot export from another
/// crate.
struct TwoFactorPromptBridge(Arc<dyn OnePasswordTwoFactorPrompt>);

#[async_trait::async_trait]
impl OnePasswordTwoFactorUi for TwoFactorPromptBridge {
    async fn provide_totp(&self, attempt: u32) -> OnePasswordTotpResult {
        // A prompt that throws produces no code either, so it reads as the user cancelling.
        match self.0.provide_totp(attempt).await {
            Ok(Some(code)) => OnePasswordTotpResult::Code(code),
            Ok(None) | Err(_) => OnePasswordTotpResult::Cancel,
        }
    }
}
