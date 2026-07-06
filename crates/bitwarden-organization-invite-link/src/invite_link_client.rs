use bitwarden_core::{
    Client, FromClient, OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
};
use bitwarden_crypto::KeyStore;
use bitwarden_error::bitwarden_error;
use bitwarden_organization_crypto::{Invite, InviteBundle, InviteKeyBundleError, InviteKeyData};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

/// Errors returned from [`InviteLinkClient`] operations.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum OrganizationInviteCryptoBundleError {
    /// Failed to generate the invite key bundle.
    #[error("Key bundle generation failed: {0}")]
    BundleGenerationFailed(#[from] InviteKeyBundleError),
    /// Failed to unseal the invite key envelope using the organization key.
    #[error("Failed to unseal invite key: {0}")]
    UnsealingFailed(InviteKeyBundleError),
}

/// The cryptographic bundle returned when generating an organization member invite link.
///
/// - `invite_key`: raw invite key encoded as base64Url. **MUST NOT be sent to the server.**
/// - `invite`: invite key sealed with the organization key, serialized as an EncString. Safe to
///   send to the server.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInviteCryptoBundle {
    /// Raw invite key. CRITICAL: MUST NOT be sent to the server.
    #[cfg_attr(feature = "wasm", tsify(type = "InviteKeyData"))]
    pub invite_key: InviteKeyData,
    /// Invite key sealed with the organization key. Safe to send to the server.
    #[cfg_attr(feature = "wasm", tsify(type = "Invite"))]
    pub invite: Invite,
}

/// Client for organization invite link cryptographic operations.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct InviteLinkClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl InviteLinkClient {
    /// Generates a new [`OrganizationInviteCryptoBundle`] sealed with the organization's key.
    ///
    /// The organization key is looked up from the client's key store via
    /// [`SymmetricKeySlotId::Organization`]; the caller does not need to provide it directly.
    ///
    /// Each call produces a unique invite key sampled from a secure cryptographic source.
    ///
    /// # Security
    /// The returned `invite_key` MUST NOT be sent to the server.
    pub fn make_invite(
        &self,
        organization_id: OrganizationId,
    ) -> Result<OrganizationInviteCryptoBundle, OrganizationInviteCryptoBundleError> {
        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);
        let bundle = InviteBundle::make(org_key, &mut ctx)?;
        Ok(OrganizationInviteCryptoBundle {
            invite_key: bundle.dangerous_get_raw_invite_key().clone(),
            invite: bundle.get_envelope().clone(),
        })
    }

    /// Unseals a `sealed_invite_key_envelope` using the organization's key, returning the raw
    /// invite key as [`InviteKeyData`].
    pub fn get_invite_key(
        &self,
        organization_id: OrganizationId,
        invite: Invite,
    ) -> Result<InviteKeyData, OrganizationInviteCryptoBundleError> {
        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);
        invite
            .unseal(org_key, &mut ctx)
            .map_err(OrganizationInviteCryptoBundleError::UnsealingFailed)
    }
}

/// Extension trait that exposes [`InviteLinkClient`] on [`Client`].
pub trait InviteLinkClientExt {
    /// Returns an [`InviteLinkClient`] backed by this client's key store.
    fn invite_link(&self) -> InviteLinkClient;
}

impl InviteLinkClientExt for Client {
    fn invite_link(&self) -> InviteLinkClient {
        InviteLinkClient::from_client(self)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::create_test_crypto_with_user_and_org_key;
    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};

    use super::*;

    fn make_client(org_id: OrganizationId) -> InviteLinkClient {
        let user_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let key_store = create_test_crypto_with_user_and_org_key(user_key, org_id, org_key);
        InviteLinkClient { key_store }
    }

    #[test]
    fn generate_invite_crypto_bundle_returns_non_empty_fields() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle = client.make_invite(org_id).unwrap();

        assert!(!String::from(&bundle.invite_key).is_empty());
        assert!(!String::from(&bundle.invite).is_empty());
    }

    #[test]
    fn envelope_unseals_to_raw_invite_key() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle = client.make_invite(org_id).unwrap();
        let unsealed = client
            .get_invite_key(org_id, bundle.invite.clone())
            .unwrap();

        assert_eq!(bundle.invite_key, unsealed);
    }

    #[test]
    fn two_calls_produce_different_invite_keys() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle1 = client.make_invite(org_id).unwrap();
        let bundle2 = client.make_invite(org_id).unwrap();

        assert_ne!(
            String::from(&bundle1.invite_key),
            String::from(&bundle2.invite_key)
        );
    }

    #[test]
    fn sealed_invite_serializes_as_stable_base64_wire_format() {
        // The invite is serialized as a base64-encoded CBOR structure (the
        // extendable wire format). It must round-trip back to an identical
        // invite that still unseals to the original invite key.
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle = client.make_invite(org_id).unwrap();
        let invite_str = String::from(&bundle.invite);

        let reparsed: Invite = invite_str
            .parse()
            .expect("serialized invite must parse back from its base64 wire format");
        let unsealed = client.get_invite_key(org_id, reparsed).unwrap();
        assert_eq!(bundle.invite_key, unsealed);
    }

    #[test]
    fn unseal_with_wrong_organization_id_fails() {
        let org_id = OrganizationId::new_v4();
        let other_org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle = client.make_invite(org_id).unwrap();
        let result = client.get_invite_key(other_org_id, bundle.invite);

        assert!(matches!(
            result,
            Err(OrganizationInviteCryptoBundleError::UnsealingFailed(_))
        ));
    }

    #[test]
    fn generate_with_unknown_organization_id_fails() {
        let org_id = OrganizationId::new_v4();
        let other_org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let result = client.make_invite(other_org_id);

        assert!(matches!(
            result,
            Err(OrganizationInviteCryptoBundleError::BundleGenerationFailed(
                _
            ))
        ));
    }
}
