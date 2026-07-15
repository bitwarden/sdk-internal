use bitwarden_core::{
    Client, FromClient, OrganizationId,
    key_management::{KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId},
};
use bitwarden_crypto::{
    CoseKeyThumbprintExt, CryptoError, EncString, KeyStore, PublicKey, SymmetricKeyAlgorithm,
    UnsignedSharedKey,
};
use bitwarden_error::bitwarden_error;
use bitwarden_organization_crypto::{Invite, InviteBundle, InviteKeyBundleError, InviteSecret};
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
    /// Failed to unseal the invite using the organization key.
    #[error("Failed to unseal invite: {0}")]
    UnsealingFailed(InviteKeyBundleError),
    /// A cryptographic operation on the organization's key material failed.
    #[error("Cryptographic operation failed: {0}")]
    CryptoOperationFailed(#[from] CryptoError),
    /// The organization public key does not match the thumbprint bound into the invite.
    #[error("Organization public key does not match the invite")]
    ThumbprintMismatch,
}

/// The cryptographic bundle returned when generating an organization member invite link.
///
/// - `invite_secret`: raw invite secret encoded as base64Url. **MUST NOT be sent to the server.**
/// - `invite`: the invite binding the organization key, invite key, and invite secret, serialized
///   as base64. Safe to send to the server.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[serde(rename_all = "camelCase")]
pub struct OrganizationInviteCryptoBundle {
    /// Raw invite secret. CRITICAL: MUST NOT be sent to the server.
    #[cfg_attr(feature = "wasm", tsify(type = "InviteSecret"))]
    pub invite_secret: InviteSecret,
    /// The invite. Safe to send to the server.
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
    /// The returned `invite_secret` MUST NOT be sent to the server.
    pub fn make_invite(
        &self,
        organization_id: OrganizationId,
        wrapped_private_key: EncString,
    ) -> Result<OrganizationInviteCryptoBundle, OrganizationInviteCryptoBundleError> {
        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);

        let bundle = InviteBundle::make_for_private_key(org_key, &wrapped_private_key, &mut ctx)?;
        Ok(OrganizationInviteCryptoBundle {
            invite_secret: bundle.dangerous_get_raw_invite_secret().clone(),
            invite: bundle.get_envelope().clone(),
        })
    }

    /// Recovers the raw [`InviteSecret`] from an `invite` using the organization's key (the admin
    /// direction, e.g. to reconstruct an invite link).
    pub fn get_invite_secret(
        &self,
        organization_id: OrganizationId,
        invite: Invite,
    ) -> Result<InviteSecret, OrganizationInviteCryptoBundleError> {
        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);
        let invite_key = invite
            .invite_key_from_organization_key(org_key, &mut ctx)
            .map_err(OrganizationInviteCryptoBundleError::UnsealingFailed)?;
        invite
            .get_invite_secret(invite_key, &mut ctx)
            .map_err(OrganizationInviteCryptoBundleError::UnsealingFailed)
    }

    /// Whether confirmation is enabled on the given `invite` (i.e. whether the organization key can
    /// be recovered from the invite).
    pub fn supports_confirmation(&self, invite: Invite) -> bool {
        invite.supports_confirmation()
    }

    /// Enables confirmation on the given `invite`, sealing the organization key to the invite key
    /// so an invitee can self-confirm. Returns the updated invite.
    pub fn enable_confirmation(
        &self,
        organization_id: OrganizationId,
        mut invite: Invite,
    ) -> Result<Invite, OrganizationInviteCryptoBundleError> {
        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);
        invite
            .enable_confirmation(org_key, &mut ctx)
            .map_err(OrganizationInviteCryptoBundleError::BundleGenerationFailed)?;
        Ok(invite)
    }

    /// Disables confirmation on the given `invite`, removing the organization-key envelope. Returns
    /// the updated invite.
    pub fn disable_confirmation(&self, mut invite: Invite) -> Invite {
        invite.disable_confirmation();
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
        let mut ctx = self.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(organization_id);

        // Verify the organization public key we are about to encapsulate to matches the thumbprint
        // bound into the invite, so a substituted public key cannot capture the organization key.
        let invite_key = invite
            .invite_key_from_organization_key(org_key, &mut ctx)
            .map_err(OrganizationInviteCryptoBundleError::UnsealingFailed)?;
        let bound_thumbprint = invite
            .get_public_key_thumbprint(invite_key, &mut ctx)
            .map_err(OrganizationInviteCryptoBundleError::UnsealingFailed)?;
        if bound_thumbprint != organization_public_key.thumbprint()? {
            return Err(OrganizationInviteCryptoBundleError::ThumbprintMismatch);
        }

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
    /// key store (as `make_invite` expects), returning it alongside the matching public key.
    fn make_org_keypair(
        client: &InviteLinkClient,
        org_id: OrganizationId,
    ) -> (EncString, PublicKey) {
        let mut ctx = client.key_store.context();
        let org_key = SymmetricKeySlotId::Organization(org_id);
        let private_key_id =
            ctx.make_private_key(bitwarden_crypto::PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let public_key = ctx
            .get_public_key(private_key_id)
            .expect("getting the public key should succeed");
        let wrapped = ctx
            .wrap_private_key(org_key, private_key_id)
            .expect("wrapping the private key with the org key should succeed");
        (wrapped, public_key)
    }

    /// Convenience wrapper returning only the wrapped private key.
    fn make_wrapped_private_key(client: &InviteLinkClient, org_id: OrganizationId) -> EncString {
        make_org_keypair(client, org_id).0
    }

    #[test]
    fn generate_invite_crypto_bundle_returns_non_empty_fields() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();

        assert!(!String::from(&bundle.invite_secret).is_empty());
        assert!(!String::from(&bundle.invite).is_empty());
    }

    #[test]
    fn invite_recovers_invite_secret() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();
        let recovered = client
            .get_invite_secret(org_id, bundle.invite.clone())
            .unwrap();

        assert_eq!(bundle.invite_secret, recovered);
    }

    #[test]
    fn two_calls_produce_different_invite_secrets() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle1 = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();
        let bundle2 = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();

        assert_ne!(
            String::from(&bundle1.invite_secret),
            String::from(&bundle2.invite_secret)
        );
    }

    #[test]
    fn sealed_invite_serializes_as_stable_base64_wire_format() {
        // The invite is serialized as a base64-encoded CBOR structure (the
        // extendable wire format). It must round-trip back to an identical
        // invite that still recovers the original invite secret.
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();
        let invite_str = String::from(&bundle.invite);

        let reparsed: Invite = invite_str
            .parse()
            .expect("serialized invite must parse back from its base64 wire format");
        let recovered = client.get_invite_secret(org_id, reparsed).unwrap();
        assert_eq!(bundle.invite_secret, recovered);
    }

    #[test]
    fn get_invite_secret_with_wrong_organization_id_fails() {
        let org_id = OrganizationId::new_v4();
        let other_org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();
        let result = client.get_invite_secret(other_org_id, bundle.invite);

        assert!(matches!(
            result,
            Err(OrganizationInviteCryptoBundleError::UnsealingFailed(_))
        ));
    }

    #[test]
    fn confirmation_can_be_toggled() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let bundle = client
            .make_invite(org_id, make_wrapped_private_key(&client, org_id))
            .unwrap();

        // New invites are created with confirmation enabled.
        assert!(client.supports_confirmation(bundle.invite.clone()));

        let disabled = client.disable_confirmation(bundle.invite.clone());
        assert!(!client.supports_confirmation(disabled.clone()));

        let re_enabled = client.enable_confirmation(org_id, disabled).unwrap();
        assert!(client.supports_confirmation(re_enabled));
    }

    #[test]
    fn enroll_account_recovery_succeeds_with_matching_public_key() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let (wrapped, public_key) = make_org_keypair(&client, org_id);
        let bundle = client.make_invite(org_id, wrapped).unwrap();

        client
            .enroll_account_recovery(org_id, bundle.invite, public_key)
            .expect("enrollment with the matching org public key should succeed");
    }

    #[test]
    fn enroll_account_recovery_fails_with_mismatched_public_key() {
        let org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        let (wrapped, _public_key) = make_org_keypair(&client, org_id);
        let bundle = client.make_invite(org_id, wrapped).unwrap();
        // A different key pair whose thumbprint is not bound into the invite.
        let (_other_wrapped, other_public_key) = make_org_keypair(&client, org_id);

        let result = client.enroll_account_recovery(org_id, bundle.invite, other_public_key);
        assert!(matches!(
            result,
            Err(OrganizationInviteCryptoBundleError::ThumbprintMismatch)
        ));
    }

    #[test]
    fn generate_with_unknown_organization_id_fails() {
        let org_id = OrganizationId::new_v4();
        let other_org_id = OrganizationId::new_v4();
        let client = make_client(org_id);

        // The wrapped private key can only be produced for a known org, so use the known org's
        // wrapped key but pass an unknown org id: unwrapping the private key with the missing org
        // key fails inside `make_for_private_key`.
        let wrapped = make_wrapped_private_key(&client, org_id);
        let result = client.make_invite(other_org_id, wrapped);

        assert!(matches!(
            result,
            Err(OrganizationInviteCryptoBundleError::BundleGenerationFailed(
                InviteKeyBundleError::InvalidPrivateKey
            ))
        ));
    }
}
