use std::str::FromStr;

use bitwarden_crypto::{BitwardenLegacyKeyBytes, KeyStore, SymmetricCryptoKey, key_slot_ids};
use bitwarden_error::bitwarden_error;
use bitwarden_organization_crypto::{InviteKeyBundle, InviteKeyBundleError, InviteKeyEnvelope};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;

/// Errors from generating an organization invite crypto bundle.
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum OrganizationInviteCryptoBundleError {
    #[error("Invalid organization key")]
    InvalidOrganizationKey,
    #[error("Key bundle generation failed: {0}")]
    BundleGenerationFailed(#[from] InviteKeyBundleError),
    #[error("Invalid sealed invite key envelope: {0}")]
    InvalidSealedEnvelope(InviteKeyBundleError),
    #[error("Failed to unseal invite key: {0}")]
    UnsealingFailed(InviteKeyBundleError),
}

/// The cryptographic bundle for an organization member invite.
///
/// - `invite_key`: raw invite key encoded as base64Url. **MUST NOT be sent to the server.**
/// - `sealed_invite_key_envelope`: invite key sealed with the org key, serialized as a Bitwarden
///   EncString (`"2.iv|data|mac"`). Safe to send to the server.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInviteCryptoBundle {
    /// Raw invite key as base64Url. CRITICAL: MUST NOT be sent to the server.
    pub invite_key: String,
    /// Invite key sealed with the organization key, as a Bitwarden EncString (`"2.iv|data|mac"`).
    pub sealed_invite_key_envelope: String,
}

impl std::fmt::Debug for OrganizationInviteCryptoBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrganizationInviteCryptoBundle")
            .field("invite_key", &"<REDACTED>")
            .field(
                "sealed_invite_key_envelope",
                &self.sealed_invite_key_envelope,
            )
            .finish()
    }
}

/// Generates a new [`OrganizationInviteCryptoBundle`] sealed with the provided organization key.
///
/// Each call produces a unique, non-deterministic invite key.
///
/// # Security
/// The `invite_key` field MUST NOT be sent to the server.
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
pub fn generate_organization_invite_crypto_bundle(
    org_key: Vec<u8>,
) -> Result<OrganizationInviteCryptoBundle, OrganizationInviteCryptoBundleError> {
    let tmp_store: KeyStore<LocalKeySlotIds> = KeyStore::default();
    let mut context = tmp_store.context();

    let org_key = SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(org_key))
        .map_err(|_| OrganizationInviteCryptoBundleError::InvalidOrganizationKey)?;
    let org_key_slot = context.add_local_symmetric_key(org_key);

    let bundle = InviteKeyBundle::make(org_key_slot, &mut context)?;

    Ok(OrganizationInviteCryptoBundle {
        invite_key: String::from(bundle.dangerous_get_raw_invite_key()),
        sealed_invite_key_envelope: String::from(bundle.get_sealed_invite_key_envelope()),
    })
}

/// Unseals a `sealedInviteKeyEnvelope` (produced by [`generate_organization_invite_crypto_bundle`])
/// using the organization key, returning the raw invite key as a base64Url string.
///
/// The returned invite key is safe to embed in a URL fragment for distribution to invitees.
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
pub fn unseal_organization_invite_key(
    org_key: Vec<u8>,
    sealed_invite_key_envelope: String,
) -> Result<String, OrganizationInviteCryptoBundleError> {
    let tmp_store: KeyStore<LocalKeySlotIds> = KeyStore::default();
    let mut context = tmp_store.context();

    let org_key = SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(org_key))
        .map_err(|_| OrganizationInviteCryptoBundleError::InvalidOrganizationKey)?;
    let org_key_slot = context.add_local_symmetric_key(org_key);

    let envelope = InviteKeyEnvelope::from_str(&sealed_invite_key_envelope)
        .map_err(OrganizationInviteCryptoBundleError::InvalidSealedEnvelope)?;
    let invite_key_data = envelope
        .unseal(org_key_slot, &mut context)
        .map_err(OrganizationInviteCryptoBundleError::UnsealingFailed)?;

    Ok(String::from(&invite_key_data))
}

key_slot_ids! {
    #[symmetric]
    enum LocalSymmetricKeySlotId {
        #[local]
        Local(LocalId),
    }

    #[private]
    enum LocalPrivateKeySlotId {
        #[local]
        Local(LocalId),
    }

    #[signing]
    enum LocalSigningKeySlotId {
        #[local]
        Local(LocalId),
    }

    LocalKeySlotIds => LocalSymmetricKeySlotId, LocalPrivateKeySlotId, LocalSigningKeySlotId;
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::SymmetricCryptoKey;

    use super::*;

    fn make_org_key() -> Vec<u8> {
        SymmetricCryptoKey::make_aes256_cbc_hmac_key()
            .to_encoded()
            .to_vec()
    }

    #[test]
    fn test_bundle_returns_valid_non_empty_strings() {
        let bundle = generate_organization_invite_crypto_bundle(make_org_key()).unwrap();
        assert!(!bundle.invite_key.is_empty());
        assert!(!bundle.sealed_invite_key_envelope.is_empty());
    }

    #[test]
    fn test_envelope_unseals_to_raw_invite_key() {
        let org_key_bytes = make_org_key();
        let bundle = generate_organization_invite_crypto_bundle(org_key_bytes.clone()).unwrap();

        let unsealed = unseal_organization_invite_key(
            org_key_bytes,
            bundle.sealed_invite_key_envelope.clone(),
        )
        .unwrap();

        assert_eq!(bundle.invite_key, unsealed);
    }

    #[test]
    fn test_two_calls_produce_different_invite_keys() {
        let org_key = make_org_key();
        let bundle1 = generate_organization_invite_crypto_bundle(org_key.clone()).unwrap();
        let bundle2 = generate_organization_invite_crypto_bundle(org_key).unwrap();
        assert_ne!(bundle1.invite_key, bundle2.invite_key);
    }

    #[test]
    fn test_sealed_invite_key_envelope_is_encstring_text_format() {
        // The server validates EncryptedInviteKey as a Bitwarden EncString text
        // format (e.g. "2.iv|data|mac").
        let bundle = generate_organization_invite_crypto_bundle(make_org_key()).unwrap();
        let envelope = &bundle.sealed_invite_key_envelope;
        assert!(
            envelope.parse::<bitwarden_crypto::EncString>().is_ok(),
            "sealed_invite_key_envelope must parse as a valid EncString, got: {envelope}"
        );
    }

    #[test]
    fn test_invalid_org_key_returns_error() {
        let result = generate_organization_invite_crypto_bundle(vec![0u8; 4]);
        assert!(matches!(
            result,
            Err(OrganizationInviteCryptoBundleError::InvalidOrganizationKey)
        ));
    }

    #[test]
    fn test_unseal_with_wrong_org_key_fails() {
        let org_key_1 = make_org_key();
        let org_key_2 = make_org_key();

        let bundle = generate_organization_invite_crypto_bundle(org_key_1).unwrap();

        let result = unseal_organization_invite_key(org_key_2, bundle.sealed_invite_key_envelope);

        assert!(
            result.is_err(),
            "Unsealing with the wrong org key must fail"
        );
    }
}
