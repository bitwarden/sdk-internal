//! Cryptographic helpers used by the access connector.
//!
//! The org slot is keyed by the [`OrganizationId`] from the access token's `organization` claim.
//! The cipher half of a rotation lives in `bitwarden_pam::rotation`.

use bitwarden_access_token::{AccessToken, AccessTokenError};
use bitwarden_core::{
    OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::KeyStore;
use thiserror::Error;

/// Errors produced by the cryptographic helpers in this module.
#[derive(Debug, Error)]
pub(crate) enum CryptoModuleError {
    /// The encrypted payload could not be decoded or decrypted.
    #[error("org-key payload is invalid")]
    InvalidPayload,

    /// The decrypted payload does not contain a valid org key.
    #[error("org-key payload does not contain a valid encryption key")]
    InvalidOrgKey,

    /// A generic cryptographic operation failed.
    #[error("cryptographic operation failed")]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

/// Decrypt the identity server's `encrypted_payload` with `token`'s derived key and install the org
/// key into `store`.
pub(crate) fn unwrap_org_key(
    store: &KeyStore<KeySlotIds>,
    organization_id: OrganizationId,
    token: &AccessToken,
    encrypted_payload: &str,
) -> Result<(), CryptoModuleError> {
    let mut ctx = store.context_mut();

    token
        .open_payload(
            &mut ctx,
            encrypted_payload,
            SymmetricKeySlotId::Organization(organization_id),
        )
        .map_err(|e| match e {
            AccessTokenError::InvalidPayload => CryptoModuleError::InvalidPayload,
            AccessTokenError::InvalidOrgKey => CryptoModuleError::InvalidOrgKey,
            AccessTokenError::Crypto(c) => CryptoModuleError::Crypto(c),
        })
}

#[cfg(test)]
mod tests {
    use bitwarden_access_token::{AccessTokenKind, make_access_token_secrets};
    use bitwarden_crypto::{
        KeyDecryptable, PrimitiveEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm,
    };
    use uuid::uuid;

    use super::*;
    use crate::test_support::test_org_id as org_id;

    fn org_slot() -> SymmetricKeySlotId {
        SymmetricKeySlotId::Organization(org_id())
    }

    fn make_store_with_org_key() -> (KeyStore<KeySlotIds>, SymmetricCryptoKey) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);

        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(org_slot(), org_key.clone())
            .expect("set_symmetric_key");

        (store, org_key)
    }

    /// Mints a token the way `bitwarden-pam` does, keyed to the organization key in
    /// `issuer_store`, plus the `encrypted_payload` that goes with it.
    fn mint_token_and_payload(issuer_store: &KeyStore<KeySlotIds>) -> (AccessToken, String) {
        let secrets = {
            let mut ctx = issuer_store.context_mut();
            make_access_token_secrets(&mut ctx, org_slot(), AccessTokenKind::AccessConnector)
                .expect("mint secrets")
        };
        let encrypted_payload = secrets.encrypted_payload.to_string();
        let token_str = secrets.into_token(uuid!("22222222-2222-2222-2222-222222222222"), "secret");
        let token = AccessToken::parse(&token_str, AccessTokenKind::AccessConnector)
            .expect("the token parses");
        (token, encrypted_payload)
    }

    #[test]
    fn unwrap_org_key_round_trip() {
        let (issuer_store, org_key) = make_store_with_org_key();
        let (token, encrypted_payload) = mint_token_and_payload(&issuer_store);

        let store: KeyStore<KeySlotIds> = KeyStore::default();
        assert!(!store.context().has_symmetric_key(org_slot()));

        unwrap_org_key(&store, org_id(), &token, &encrypted_payload).expect("unwrap_org_key");

        // Probe that the org key is installed.
        let probe = "probe value";
        let encrypted_probe = {
            let mut ctx = store.context();
            probe.encrypt(&mut ctx, org_slot()).expect("encrypt probe")
        };

        let decrypted: String = encrypted_probe
            .decrypt_with_key(&org_key)
            .expect("decrypt probe");
        assert_eq!(decrypted, probe);
    }

    #[test]
    fn unwrap_org_key_bad_payload_returns_error() {
        let (issuer_store, _org_key) = make_store_with_org_key();
        let (token, _payload) = mint_token_and_payload(&issuer_store);
        let store: KeyStore<KeySlotIds> = KeyStore::default();

        let result = unwrap_org_key(&store, org_id(), &token, "not-an-enc-string");
        assert!(
            matches!(result, Err(CryptoModuleError::InvalidPayload)),
            "expected InvalidPayload, got {result:?}",
        );
    }
}
