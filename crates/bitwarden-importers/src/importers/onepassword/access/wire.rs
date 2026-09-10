//! serde DTOs for every 1Password endpoint.
//!
//! These carry only the fields the client reads. serde ignores everything else on the wire, so the
//! structs stay small while remaining forward compatible with the full server responses.

use serde::{Deserialize, Serialize};

/// The JSON "opdata" envelope as it appears on the wire.
///
/// It is also serialized back to the server as the request body of the encrypted POST endpoints.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct EncryptedEnvelope {
    pub kid: String,
    pub enc: String,
    pub cty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
    pub data: String,
}

/// An RSA private key JWK as it appears on the wire.
///
/// Extra JWK members (`dp`, `dq`, `qi`, `alg`, `kty`, `ext`) are ignored: the CRT values are
/// recomputed from `p` and `q` when the key is built.
#[derive(Deserialize)]
pub(super) struct RsaKeyJwk {
    pub kid: String,
    pub e: String,
    pub n: String,
    pub p: String,
    pub q: String,
    pub d: String,
}

/// The decrypted AES key JSON.
#[derive(Deserialize)]
pub(super) struct AesKeyJson {
    pub kid: String,
    pub k: String,
}

/// The `v1/account/keysets` payload.
#[derive(Debug, Deserialize)]
pub(super) struct KeysetsInfo {
    pub keysets: Vec<KeysetInfo>,
}

/// A single keyset.
#[derive(Debug, Deserialize)]
pub(super) struct KeysetInfo {
    pub uuid: String,
    #[serde(default, rename = "encryptedBy")]
    pub encrypted_by: String,
    pub sn: i64,
    #[serde(rename = "encSymKey")]
    pub enc_sym_key: KeyDerivationInfo,
    #[serde(rename = "encPriKey")]
    pub enc_pri_key: EncryptedEnvelope,
}

/// An encrypted symmetric key envelope that additionally carries the KDF parameters for the master
/// keyset (`alg`/`p2s`/`p2c`).
#[derive(Debug, Deserialize)]
pub(super) struct KeyDerivationInfo {
    pub kid: String,
    pub enc: String,
    pub cty: String,
    #[serde(default)]
    pub iv: Option<String>,
    pub data: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub p2s: Option<String>,
    #[serde(default)]
    pub p2c: u32,
}

impl KeyDerivationInfo {
    /// The envelope half, without the KDF parameters.
    pub(super) fn envelope(&self) -> EncryptedEnvelope {
        EncryptedEnvelope {
            kid: self.kid.clone(),
            enc: self.enc.clone(),
            cty: self.cty.clone(),
            iv: self.iv.clone(),
            data: self.data.clone(),
        }
    }
}

/// Response from `v2/auth/methods`.
#[derive(Debug, Deserialize)]
pub(super) struct LoginInfo {
    #[serde(rename = "authMethods")]
    pub auth_methods: Vec<AuthMethod>,
}

/// A single auth method offered for an account.
#[derive(Debug, Deserialize)]
pub(super) struct AuthMethod {
    #[serde(rename = "type")]
    pub kind: String,
}

/// Response from `v3/auth/start`.
///
/// `status` drives the state machine: `ok` carries the SRP parameters, while
/// `device-not-registered` and `device-deleted` ask the client to (re)authorize the device and
/// retry.
#[derive(Debug, Deserialize)]
pub(super) struct NewSession {
    pub status: String,
    #[serde(rename = "sessionID")]
    pub session_id: String,
    #[serde(rename = "accountKeyFormat")]
    pub key_format: Option<String>,
    #[serde(rename = "accountKeyUuid")]
    pub key_uuid: Option<String>,
    #[serde(rename = "userAuth")]
    pub auth: Option<UserAuth>,
}

/// The SRP parameters carried by a successful `NewSession`.
#[derive(Debug, Deserialize)]
pub(super) struct UserAuth {
    pub method: String,
    #[serde(rename = "alg")]
    pub algorithm: String,
    pub iterations: u32,
    pub salt: String,
}

/// Response from `v1/device` and `v1/device/{uuid}/reauthorize`.
#[derive(Debug, Deserialize)]
pub(super) struct SuccessStatus {
    pub success: i32,
}

/// Response from `v2/auth` (the SRP A -> B exchange).
#[derive(Debug, Deserialize)]
pub(super) struct AForB {
    #[serde(rename = "userB")]
    pub b: String,
}

/// Response from `v2/auth/confirm-key`.
#[derive(Debug, Deserialize)]
pub(super) struct ServerHash {
    #[serde(rename = "serverVerifyHash")]
    pub server_verify_hash: String,
}

/// Response from `v2/auth/complete` (decrypted).
#[derive(Debug, Deserialize)]
pub(super) struct AuthComplete {
    pub mfa: Option<MfaInfo>,
}

/// The set of 2FA methods enabled for an account.
///
/// Only the enabled flags are modelled: TOTP is the one interactive method implemented, so the
/// per-method parameters (WebAuthn challenge, Duo host, and so on) are not read.
#[derive(Debug, Deserialize)]
pub(super) struct MfaInfo {
    #[serde(rename = "totp")]
    pub google_auth: Option<BasicMfa>,
    #[serde(rename = "webAuthn")]
    pub web_authn: Option<BasicMfa>,
    pub duo: Option<BasicMfa>,
    #[serde(rename = "dsecret")]
    pub remember_me: Option<BasicMfa>,
}

impl MfaInfo {
    /// Whether TOTP (Google Authenticator) is enabled, the only interactive method supported.
    pub(super) fn totp_enabled(&self) -> bool {
        self.google_auth.as_ref().is_some_and(|f| f.enabled)
    }

    /// Names of the enabled 2FA methods, in the order 1Password reports them.
    pub(super) fn enabled_methods(&self) -> Vec<&'static str> {
        let mut methods = Vec::new();
        for (factor, name) in [
            (&self.google_auth, "TOTP"),
            (&self.web_authn, "WebAuthn"),
            (&self.duo, "Duo"),
            (&self.remember_me, "remember-me"),
        ] {
            if factor.as_ref().is_some_and(|f| f.enabled) {
                methods.push(name);
            }
        }
        methods
    }
}

/// The `{ "enabled": bool }` shared by every 2FA method entry.
#[derive(Debug, Deserialize)]
pub(super) struct BasicMfa {
    pub enabled: bool,
}

/// A server error body.
#[derive(Debug, Deserialize)]
pub(super) struct ErrorResponse {
    #[serde(rename = "errorCode")]
    pub code: i32,
    #[serde(rename = "errorMessage")]
    pub message: String,
}

/// A server failure body used by some endpoints instead of `Error`.
#[derive(Debug, Deserialize)]
pub(super) struct FailureReason {
    pub reason: String,
}

/// Response from `v1/account` (decrypted). Only the vault list is used.
#[derive(Debug, Deserialize)]
pub(super) struct AccountInfo {
    pub vaults: Vec<VaultInfo>,
}

/// A vault entry in the account info.
#[derive(Debug, Deserialize)]
pub(super) struct VaultInfo {
    pub uuid: String,
    #[serde(rename = "encAttrs")]
    pub enc_attrs: EncryptedEnvelope,
    pub access: Vec<VaultAccess>,
}

/// An access-control entry carrying the vault key encrypted for a key we may hold.
#[derive(Debug, Deserialize)]
pub(super) struct VaultAccess {
    pub acl: i32,
    #[serde(rename = "encVaultKey")]
    pub enc_vault_key: EncryptedEnvelope,
}

/// Decrypted vault attributes.
#[derive(Deserialize)]
pub(super) struct VaultAttributes {
    pub name: Option<String>,
    pub desc: Option<String>,
}

/// A page of vault items. The last page is marked `batchComplete`.
#[derive(Debug, Deserialize)]
pub(super) struct VaultItemsBatch {
    #[serde(rename = "contentVersion")]
    pub version: i64,
    #[serde(rename = "batchComplete")]
    pub complete: bool,
    pub items: Option<Vec<VaultItem>>,
}

/// A single encrypted vault item.
#[derive(Debug, Deserialize)]
pub(super) struct VaultItem {
    pub uuid: String,
    #[serde(rename = "templateUuid")]
    pub template_uuid: String,
    pub trashed: String,
    #[serde(rename = "encOverview")]
    pub enc_overview: EncryptedEnvelope,
    #[serde(rename = "encDetails")]
    pub enc_details: EncryptedEnvelope,
}

/// A decrypted item overview.
#[derive(Deserialize)]
pub struct VaultItemOverview {
    pub title: Option<String>,
    pub ainfo: Option<String>,
    pub url: Option<String>,
    #[serde(rename = "URLs")]
    pub urls: Option<Vec<VaultItemUrl>>,
    pub tags: Option<Vec<String>>,
}

/// A URL entry in an item overview.
#[derive(Deserialize)]
pub struct VaultItemUrl {
    #[serde(rename = "l")]
    pub name: Option<String>,
    #[serde(rename = "u")]
    pub url: Option<String>,
}

/// Decrypted item details.
#[derive(Deserialize)]
pub struct VaultItemDetails {
    #[serde(rename = "notesPlain")]
    pub note: Option<String>,
    pub fields: Option<Vec<VaultItemField>>,
    pub sections: Option<Vec<VaultItemSection>>,
    /// The secret of a Password-category item, which carries no `fields`.
    pub password: Option<String>,
    #[serde(rename = "passwordHistory")]
    pub password_history: Option<Vec<VaultItemPasswordHistory>>,
}

/// A superseded password and the unix time it was replaced, oldest first.
#[derive(Deserialize)]
pub struct VaultItemPasswordHistory {
    pub value: Option<String>,
    pub time: Option<i64>,
}

/// A designation-based login field (username/password).
#[derive(Deserialize)]
pub struct VaultItemField {
    pub designation: Option<String>,
    pub value: Option<String>,
    pub name: Option<String>,
    /// `T` for text, `P` for password.
    #[serde(rename = "type")]
    pub kind: Option<String>,
}

/// A titled section of fields.
#[derive(Deserialize)]
pub struct VaultItemSection {
    /// The section's stable id, such as `Section_l2bagl3iupehvr7jvrc62mjhee`.
    #[serde(rename = "name")]
    pub id: Option<String>,
    #[serde(rename = "title")]
    pub name: Option<String>,
    pub fields: Option<Vec<VaultItemSectionField>>,
}

/// A field inside a section. The value `v` can be any JSON type.
#[derive(Deserialize)]
pub struct VaultItemSectionField {
    #[serde(rename = "n")]
    pub id: Option<String>,
    #[serde(rename = "t")]
    pub name: Option<String>,
    #[serde(rename = "v")]
    pub value: Option<serde_json::Value>,
    #[serde(rename = "k")]
    pub kind: Option<String>,
    #[serde(rename = "a")]
    pub attributes: Option<VaultItemFieldAttributes>,
    /// Keyboard hints for the 1Password UI, of no use to an import.
    #[serde(rename = "inputTraits")]
    pub input_traits: Option<VaultItemInputTraits>,
}

/// How the 1Password UI should present a field's editor.
#[derive(Debug, Deserialize)]
pub struct VaultItemInputTraits {
    pub autocapitalization: Option<String>,
    pub keyboard: Option<String>,
    pub correction: Option<String>,
}

/// Extra attributes on a section field.
#[derive(Deserialize)]
pub struct VaultItemFieldAttributes {
    pub guarded: Option<String>,
    #[serde(rename = "sshKeyAttributes")]
    pub ssh_key: Option<SshKeyAttributes>,
}

/// The SSH key material carried on a `sshKey` field.
#[derive(Deserialize)]
pub struct SshKeyAttributes {
    #[serde(rename = "privateKey")]
    pub private_key: Option<String>,
    #[serde(rename = "publicKey")]
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
    #[serde(rename = "keyType")]
    pub key_type: Option<SshKeyType>,
}

/// An SSH key's type and, for RSA, its bit length.
#[derive(Debug, Deserialize)]
pub struct SshKeyType {
    #[serde(rename = "t")]
    pub kind: String,
    #[serde(rename = "c", default)]
    pub bits: i64,
}
