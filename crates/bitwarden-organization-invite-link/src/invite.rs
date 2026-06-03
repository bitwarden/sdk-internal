use bitwarden_crypto::{KeyStore, SymmetricCryptoKey, key_slot_ids};
use bitwarden_error::bitwarden_error;
use bitwarden_organization_crypto::{
    InviteKeyBundle, InviteKeyBundleError, InviteKeyData, InviteKeyEnvelope,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_FUNCTIONS: &'static str = r#"
/**
 * Generates a new organization invite crypto bundle sealed with the provided organization key.
 * The `inviteKey` field MUST NOT be sent to the server.
 */
export function generate_organization_invite_crypto_bundle(org_key: SymmetricKey): OrganizationInviteCryptoBundle;

/**
 * Unseals a sealed invite key envelope using the organization key,
 * returning the raw invite key as a base64Url string.
 */
export function unseal_organization_invite_key(org_key: SymmetricKey, sealed_invite_key_envelope: InviteKeyEnvelope): string;
"#;

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub struct OrganizationInviteLinkWasm;

/// Errors from generating an organization invite crypto bundle.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum OrganizationInviteCryptoBundleError {
    #[error("Key bundle generation failed: {0}")]
    /// Bundle Generation failed
    BundleGenerationFailed(#[from] InviteKeyBundleError),
    #[error("Invalid sealed invite key envelope: {0}")]
    /// Invalid Envelope
    InvalidSealedEnvelope(InviteKeyBundleError),
    #[error("Failed to unseal invite key: {0}")]
    /// Unsealing Envelope failed
    UnsealingFailed(InviteKeyBundleError),
}

/// The cryptographic bundle for an organization member invite.
///
/// - `invite_key`: raw invite key encoded as base64Url. **MUST NOT be sent to the server.**
/// - `sealed_invite_key_envelope`: invite key sealed with the org key, serialized as an EncString.
///   Safe to send to the server.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInviteCryptoBundle {
    /// Key data containing the raw invite key bytes as base64Url. CRITICAL: MUST NOT be sent to
    /// the server.
    #[cfg_attr(feature = "wasm", tsify(type = "InviteKeyData"))]
    pub invite_key: InviteKeyData,
    /// Invite key sealed with the organization key
    #[cfg_attr(feature = "wasm", tsify(type = "InviteKeyEnvelope"))]
    pub sealed_invite_key_envelope: InviteKeyEnvelope,
}

/// Generates a new [`OrganizationInviteCryptoBundle`] sealed with the provided organization key.
///
/// Each call produces a unique key sampled from a secure cryptographic source.
///
/// # Security
/// The `invite_key` field MUST NOT be sent to the server.
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen(skip_typescript))]
pub fn generate_organization_invite_crypto_bundle(
    org_key: SymmetricCryptoKey,
) -> Result<OrganizationInviteCryptoBundle, OrganizationInviteCryptoBundleError> {
    let tmp_store: KeyStore<LocalKeySlotIds> = KeyStore::default();
    let mut context = tmp_store.context();

    let org_key_slot = context.add_local_symmetric_key(org_key);

    let bundle = InviteKeyBundle::make(org_key_slot, &mut context)?;

    let invite_key = bundle.dangerous_get_raw_invite_key().clone();
    let sealed_invite_key_envelope = bundle.get_sealed_invite_key_envelope().clone();

    Ok(OrganizationInviteCryptoBundle {
        invite_key,
        sealed_invite_key_envelope,
    })
}

/// Unseals a `sealedInviteKeyEnvelope` (produced by [`generate_organization_invite_crypto_bundle`])
/// using the organization key, returning the raw invite key as a base64Url string.
///
/// The returned invite key is safe to embed in a URL fragment for distribution to invitees.
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen(skip_typescript))]
pub fn unseal_organization_invite_key(
    org_key: SymmetricCryptoKey,
    sealed_invite_key_envelope: InviteKeyEnvelope,
) -> Result<String, OrganizationInviteCryptoBundleError> {
    let tmp_store: KeyStore<LocalKeySlotIds> = KeyStore::default();
    let mut context = tmp_store.context();

    let org_key_slot = context.add_local_symmetric_key(org_key);

    let invite_key_data = sealed_invite_key_envelope
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

    fn make_org_key() -> SymmetricCryptoKey {
        SymmetricCryptoKey::make_aes256_cbc_hmac_key()
    }

    #[test]
    fn test_bundle_returns_valid_invite_key_and_envelope() {
        let bundle = generate_organization_invite_crypto_bundle(make_org_key()).unwrap();
        // InviteKeyData serializes as a non-empty base64Url string
        assert!(!String::from(&bundle.invite_key).is_empty());
        // InviteKeyEnvelope serializes as a non-empty EncString
        assert!(!String::from(&bundle.sealed_invite_key_envelope).is_empty());
    }

    #[test]
    fn test_envelope_unseals_to_raw_invite_key() {
        let org_key_bytes = make_org_key().to_encoded().to_vec();
        let org_key = SymmetricCryptoKey::try_from(
            &bitwarden_crypto::BitwardenLegacyKeyBytes::from(org_key_bytes.clone()),
        )
        .unwrap();
        let org_key_for_unseal = SymmetricCryptoKey::try_from(
            &bitwarden_crypto::BitwardenLegacyKeyBytes::from(org_key_bytes),
        )
        .unwrap();

        let bundle = generate_organization_invite_crypto_bundle(org_key).unwrap();

        let unsealed = unseal_organization_invite_key(
            org_key_for_unseal,
            bundle.sealed_invite_key_envelope.clone(),
        )
        .unwrap();

        assert_eq!(String::from(&bundle.invite_key), unsealed);
    }

    #[test]
    fn test_two_calls_produce_different_invite_keys() {
        let org_key1 = make_org_key();
        let org_key2 = SymmetricCryptoKey::try_from(
            &bitwarden_crypto::BitwardenLegacyKeyBytes::from(org_key1.to_encoded().to_vec()),
        )
        .unwrap();
        let bundle1 = generate_organization_invite_crypto_bundle(org_key1).unwrap();
        let bundle2 = generate_organization_invite_crypto_bundle(org_key2).unwrap();
        assert_ne!(
            String::from(&bundle1.invite_key),
            String::from(&bundle2.invite_key)
        );
    }

    #[test]
    fn test_sealed_invite_key_envelope_is_encstring_text_format() {
        // The server validates EncryptedInviteKey as a Bitwarden EncString text
        // format (e.g. "2.iv|data|mac").
        let bundle = generate_organization_invite_crypto_bundle(make_org_key()).unwrap();
        let envelope_str = String::from(&bundle.sealed_invite_key_envelope);
        assert!(
            envelope_str.parse::<bitwarden_crypto::EncString>().is_ok(),
            "sealed_invite_key_envelope must parse as a valid EncString, got: {envelope_str}"
        );
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
