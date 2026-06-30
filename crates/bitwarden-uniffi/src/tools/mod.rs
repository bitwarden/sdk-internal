use std::sync::Arc;

use bitwarden_collections::collection::Collection;
use bitwarden_exporters::{Account, ExportFormat};
use bitwarden_generators::{
    PassphraseGeneratorRequest, PasswordGeneratorRequest, UsernameGeneratorRequest,
};
use bitwarden_importers::{
    ImportOptions, ImportSummary,
    keeper::{KeeperEcKeyPair, KeeperRecordKeyType},
};
use bitwarden_vault::{Cipher, Folder};

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
    pub fn import_cxf(&self, payload: String) -> Result<Vec<Cipher>> {
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

    /// Keeper "direct" importer cryptography. Returns a stateless client exposing Keeper's
    /// wire-format crypto primitives.
    pub fn keeper_crypto(&self) -> Arc<KeeperCryptoClient> {
        Arc::new(KeeperCryptoClient(self.0.keeper_crypto()))
    }
}

#[derive(uniffi::Object)]
pub struct KeeperCryptoClient(pub(crate) bitwarden_importers::keeper::KeeperCryptoClient);

/// Keeper "direct" importer cryptography, exposed for the still-TypeScript Keeper access layer.
///
/// These primitives implement Keeper's competitor wire formats (unauthenticated AES-CBC,
/// AES-GCM with a prepended nonce, RSA PKCS#1 v1.5, ECDH-P256 → AES-GCM, and the custom
/// `encryptionParams` blob). They are not Bitwarden cryptography.
#[uniffi::export]
impl KeeperCryptoClient {
    /// Generate a new 32-byte AES encryption key.
    pub fn generate_encryption_key(&self) -> Vec<u8> {
        self.0.generate_encryption_key()
    }

    /// Decrypt an "aes-v1" packet (AES-256-CBC, PKCS#7, unauthenticated). Packet: `IV(16) || ct`.
    pub fn decrypt_aes_v1(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.0.decrypt_aes_v1(data, key)?)
    }

    /// Encrypt an "aes-v2" packet (AES-256-GCM). Output: `nonce(12) || ct || tag(16)`. A fresh
    /// random nonce is always generated, so nonce reuse cannot occur across this boundary.
    pub fn encrypt_aes_v2(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.0.encrypt_aes_v2(data, key)?)
    }

    /// Decrypt an "aes-v2" packet (AES-256-GCM). Packet: `nonce(12) || ct || tag(16)`.
    pub fn decrypt_aes_v2(&self, data: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.0.decrypt_aes_v2(data, key)?)
    }

    /// Encrypt with an RSA public key (PKCS#1 v1.5). `public_key` is PKCS#1 DER.
    pub fn encrypt_rsa(&self, data: Vec<u8>, public_key: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.0.encrypt_rsa(data, public_key)?)
    }

    /// Decrypt with an RSA private key (PKCS#1 v1.5). `private_key` is PKCS#1 DER.
    pub fn decrypt_rsa(&self, data: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.0.decrypt_rsa(data, private_key)?)
    }

    /// Generate a new P-256 key pair for Keeper's ECC scheme.
    pub fn generate_ec_key(&self) -> Result<KeeperEcKeyPair> {
        Ok(self.0.generate_ec_key()?)
    }

    /// Encrypt for an EC public key (ECDH-P256 → AES-GCM). `public_key` is an uncompressed SEC1
    /// point. Output: `ephemeralPublic(65) || aes-v2 packet`.
    pub fn encrypt_ec(&self, data: Vec<u8>, public_key: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.0.encrypt_ec(data, public_key)?)
    }

    /// Decrypt an EC-encrypted packet. `private_key` is PKCS#8 DER.
    pub fn decrypt_ec(&self, data: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.0.decrypt_ec(data, private_key)?)
    }

    /// Derive a Keeper master key from a password (PBKDF2-HMAC-SHA256, 32 bytes).
    pub fn derive_key_v1(&self, password: String, salt: Vec<u8>, iterations: u32) -> Vec<u8> {
        self.0.derive_key_v1(password, salt, iterations)
    }

    /// Derive Keeper's v1 auth hash: `SHA-256(derive_key_v1(...))`.
    pub fn derive_v1_key_hash(&self, password: String, salt: Vec<u8>, iterations: u32) -> Vec<u8> {
        self.0.derive_v1_key_hash(password, salt, iterations)
    }

    /// Derive a data key from a Keeper `encryptionParams` blob.
    pub fn decrypt_encryption_params(
        &self,
        password: String,
        encryption_params: Vec<u8>,
    ) -> Result<Vec<u8>> {
        Ok(self
            .0
            .decrypt_encryption_params(password, encryption_params)?)
    }

    /// Decrypt a record/folder key according to its [`KeeperRecordKeyType`].
    pub fn decrypt_keeper_key(
        &self,
        encrypted_key: Vec<u8>,
        key_type: KeeperRecordKeyType,
        data_key: Vec<u8>,
        rsa_private_key: Option<Vec<u8>>,
        ec_private_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        Ok(self.0.decrypt_keeper_key(
            encrypted_key,
            key_type,
            data_key,
            rsa_private_key,
            ec_private_key,
        )?)
    }

    /// Encode bytes as unpadded URL-safe base64.
    pub fn base64_url_encode(&self, data: Vec<u8>) -> String {
        self.0.base64_url_encode(data)
    }

    /// Decode unpadded URL-safe base64.
    pub fn base64_url_decode(&self, text: String) -> Result<Vec<u8>> {
        Ok(self.0.base64_url_decode(text)?)
    }
}
