use bitwarden_core::{
    Client, FromClient, OrganizationId,
    key_management::{KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId},
};
use bitwarden_crypto::{
    CryptoError, EncString, KeyStore, PublicKey, SymmetricKeyAlgorithm, UnsignedSharedKey,
};
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
    /// A cryptographic operation on the organization's key material failed.
    #[error("Cryptographic operation failed: {0}")]
    CryptoOperationFailed(#[from] CryptoError),
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
    /// `wrapped_private_key` is the organization's private key wrapped with the organization key.
    ///
    /// Each call produces a unique invite key sampled from a secure cryptographic source.
    ///
    /// # Security
    /// The returned `invite_key` MUST NOT be sent to the server.
    pub fn make_invite(
        &self,
        organization_id: OrganizationId,
        wrapped_private_key: EncString,
    ) -> Result<OrganizationInviteCryptoBundle, OrganizationInviteCryptoBundleError> {
        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);

        let private_key_id = ctx.unwrap_private_key(org_key, &wrapped_private_key)?;
        let public_key = ctx.get_public_key(private_key_id)?;
        // TODO: bind the organization public key into the invite (follow-up ticket)
        let _ = &public_key;

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

    /// Whether invite confirmation is supported. Currently always `false`.
    // TODO(Milestone 3): delegate to the invite key bundle once confirmation is implemented.
    pub fn supports_confirmation(&self) -> bool {
        false
    }

    /// Enables confirmation on the given `invite`, returning the updated invite.
    // TODO(Milestone 3): implement confirmation via the invite key bundle. Currently a stub that
    // returns the invite unchanged.
    pub fn enable_confirmation(
        &self,
        organization_id: OrganizationId,
        invite: Invite,
    ) -> Result<Invite, OrganizationInviteCryptoBundleError> {
        let _ = &organization_id;
        Ok(invite)
    }

    /// Disables confirmation on the given `invite`, returning the updated invite.
    // TODO(Milestone 3): implement confirmation via the invite key bundle. Currently a stub that
    // returns the invite unchanged.
    pub fn disable_confirmation(&self, invite: Invite) -> Invite {
        invite
    }

    /// Enrolls the organization in account recovery by encapsulating the organization key to
    /// `unsigned_public_key`, producing an [`UnsignedSharedKey`] the recovery-key holder can later
    /// decapsulate.
    pub fn enroll_account_recovery(
        &self,
        organization_id: OrganizationId,
        invite: Invite,
        organization_public_key: PublicKey,
    ) -> Result<UnsignedSharedKey, OrganizationInviteCryptoBundleError> {
        // The invite is reserved for a future milestone that binds enrollment to the invite.
        let _ = &invite;

        let ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);
        Ok(UnsignedSharedKey::encapsulate(
            org_key,
            &organization_public_key,
            &ctx,
        )?)
    }

    /// Accepts an invite by unsealing the organization key from the invite and re-encrypting it to
    /// the accepting user's own public key (retrieved from the key store), producing an
    /// [`UnsignedSharedKey`].
    // TODO(Milestone 3): unseal the organization key from the invite via the invite key bundle.
    // Until the crypto crate supports it, a placeholder key is encapsulated in its place.
    pub fn accept_and_confirm_invite(
        &self,
        invite: Invite,
    ) -> Result<UnsignedSharedKey, OrganizationInviteCryptoBundleError> {
        let _ = &invite;

        let mut ctx = self.key_store.context();
        let user_public_key = ctx.get_public_key(PrivateKeySlotId::UserPrivateKey)?;
        let placeholder_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        Ok(UnsignedSharedKey::encapsulate(
            placeholder_key,
            &user_public_key,
            &ctx,
        )?)
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

    /// Builds an organization private key wrapped with the organization key held in the client's
    /// key store, as `make_invite` expects.
    fn make_wrapped_private_key(client: &InviteLinkClient, org_id: OrganizationId) -> EncString {
        let mut ctx = client.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(org_id);
        let private_key_id =
            ctx.make_private_key(bitwarden_crypto::PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        ctx.wrap_private_key(org_key, private_key_id)
            .expect("wrapping the private key with the org key should succeed")
    }

    #[test]
    fn generate_invite_crypto_bundle_returns_non_empty_fields() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();

        assert!(!String::from(&bundle.invite_key).is_empty());
        assert!(!String::from(&bundle.invite).is_empty());
    }

    #[test]
    fn envelope_unseals_to_raw_invite_key() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();
        let unsealed = client
            .get_invite_key(org_id, bundle.invite.clone())
            .unwrap();

        assert_eq!(bundle.invite_key, unsealed);
    }

    #[test]
    fn two_calls_produce_different_invite_keys() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle1 = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();
        let bundle2 = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();

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

        let bundle = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();
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

        let bundle = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();
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

        // The wrapped private key can only be produced for a known org, so use the known org's
        // wrapped key but pass an unknown org id: unwrapping with the missing org key fails first.
        let wrapped = make_wrapped_private_key(&client, org_id);
        let result = client.make_invite(other_org_id, wrapped);

        assert!(matches!(
            result,
            Err(OrganizationInviteCryptoBundleError::CryptoOperationFailed(
                _
            ))
        ));
    }
}
