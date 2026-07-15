use std::str::FromStr;

use bitwarden_crypto::{
    CoseKeyThumbprint, CoseKeyThumbprintExt, EncString, KeySlotIds, KeyStoreContext,
    SymmetricKeyAlgorithm, generate_versioned_sealable,
    safe::{
        DataEnvelope, DataEnvelopeNamespace, HighEntropySecret, HighEntropySecretSource,
        SealableData, SealableVersionedData, SecretProtectedKeyEnvelope,
        SecretProtectedKeyEnvelopeNamespace, SymmetricKeyEnvelope, SymmetricKeyEnvelopeNamespace,
    },
};
use bitwarden_encoding::{B64, B64Url, FromStrVisitor};
use bitwarden_sensitive_value::{Sensitive, SensitiveSlice};
use rand::Rng;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use zeroize::Zeroizing;

/// Length, in bytes, of the raw invite secret. 32 bytes provides 256 bits of entropy, which is why
/// the invite secret is safe to use directly as a [`HighEntropySecret`].
const INVITE_SECRET_LEN: usize = 32;

/// The namespace binding the invite's [`SecretProtectedKeyEnvelope`] to organization invites, so it
/// cannot be substituted for an envelope minted for another purpose.
const INVITE_SECRET_ENVELOPE_NAMESPACE: SecretProtectedKeyEnvelopeNamespace =
    SecretProtectedKeyEnvelopeNamespace::OrganizationInvite;

/// The namespace binding the invite's [`SymmetricKeyEnvelope`] (the organization key wrapped by the
/// invite key) to organization invites.
const INVITE_ORG_KEY_ENVELOPE_NAMESPACE: SymmetricKeyEnvelopeNamespace =
    SymmetricKeyEnvelopeNamespace::OrganizationInvite;

/// Errors that can occur when creating or opening an invite.
#[derive(Debug, Error)]
pub enum InviteKeyBundleError {
    /// Decoding the encrypted invite failed
    #[error("Decoding failed")]
    DecodingFailed,
    /// Sealing one of the invite's envelopes failed
    #[error("Unable to seal invite")]
    KeySealingFailed,
    /// Opening one of the invite's envelopes failed
    #[error("Unable to unseal invite")]
    KeyUnsealingFailed,
    /// A required key was not found in the key store context
    #[error("Missing Key for Id: {0}")]
    MissingKeyId(String),
    /// The organization private key could not be unwrapped, or its public-key thumbprint could not
    /// be derived
    #[error("Invalid organization private key")]
    InvalidPrivateKey,
    /// The organization key cannot be recovered from the invite because confirmation is disabled
    #[error("Confirmation is not enabled on this invite")]
    ConfirmationNotEnabled,
}

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_INVITE_SECRET: &'static str = r#"
export type InviteSecret = Tagged<string, "InviteSecret">;
"#;

/// The invite secret: 32 random, high-entropy bytes carried in the invite link. It is not a keyed
/// cryptographic object; it protects the invite key. Supports WASM bindings, automatically using
/// base64Url encoding for both `wasm-bindgen` and `tsify`.
///
/// To manually encode as a `base64URL` string:
/// ```ignore
/// String::from(&invite_secret);
/// ```
/// Also supports serde serialization/deserialization using the base64Url format.
///
/// CRITICAL: This must never be sent to the server.
#[derive(Clone)]
pub struct InviteSecret(Zeroizing<[u8; INVITE_SECRET_LEN]>);

impl ConstantTimeEq for InviteSecret {
    fn ct_eq(&self, other: &InviteSecret) -> Choice {
        self.0.as_slice().ct_eq(other.0.as_slice())
    }
}

impl PartialEq for InviteSecret {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

// Manually implemented so the raw invite secret bytes are never printed.
impl std::fmt::Debug for InviteSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteSecret").finish()
    }
}

/// Exposes the invite secret as a [`HighEntropySecret`]. This is sound because the invite secret is
/// 32 bytes sampled from a CSPRNG.
impl HighEntropySecretSource for InviteSecret {
    fn provide_high_entropy_bytes(&self) -> SensitiveSlice<'_> {
        Sensitive::from(self.0.as_slice())
    }
}

impl From<&InviteSecret> for String {
    fn from(secret: &InviteSecret) -> Self {
        B64Url::from(secret.0.as_slice()).to_string()
    }
}

impl FromStr for InviteSecret {
    type Err = InviteKeyBundleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64Url::try_from(s).map_err(|_| InviteKeyBundleError::DecodingFailed)?;
        let bytes: [u8; INVITE_SECRET_LEN] = data
            .as_bytes()
            .try_into()
            .map_err(|_| InviteKeyBundleError::DecodingFailed)?;
        Ok(InviteSecret(Zeroizing::new(bytes)))
    }
}

impl<'de> Deserialize<'de> for InviteSecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for InviteSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

/// The plaintext data sealed inside the invite's [`DataEnvelope`] with the invite key.
///
/// It binds the organization public-key thumbprint (so account-recovery enrollment can verify the
/// organization key belongs to the expected identity) and a copy of the invite secret (so a holder
/// of the invite key can reconstruct the invite link).
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct InviteDataV1 {
    /// RFC 9679 COSE Key Thumbprint (SHA-256) of the organization public key.
    public_key_thumbprint: [u8; 32],
    /// The raw invite secret bytes.
    invite_secret: [u8; INVITE_SECRET_LEN],
}
impl SealableData for InviteDataV1 {}

generate_versioned_sealable!(
    InviteData,
    DataEnvelopeNamespace::OrganizationInvite,
    [
        InviteDataV1 => "1",
    ]
);

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_INVITE: &'static str = r#"
export type Invite = Tagged<string, "Invite">;
"#;

/// Cryptographic invite for an organization, built around an AES-256-GCM **invite key** that
/// acts as the hub tying everything together:
///
/// - `invite_key_wrapped_invite_data`: the `InviteData` (org public-key thumbprint + invite secret)
///   sealed with the invite key.
/// - `invite_secret_wrapped_invite_key`: the invite key sealed with the high-entropy invite secret,
///   letting an invitee (who holds only the invite secret from the link) recover the invite key.
/// - `invite_key_wrapped_organization_key`: the organization key sealed with the invite key,
///   letting a redeeming invitee recover the organization key once they hold the invite key. This
///   is **optional**: its presence is what "confirmation" means. When confirmation is enabled the
///   invitee can self-confirm by recovering the organization key; when disabled, this field is
///   absent and an admin must confirm the invitee out of band.
/// - `organization_key_wrapped_invite_key`: the invite key wrapped with the organization key,
///   letting anyone holding the organization key recover the invite key (and thus the invite data).
#[derive(Clone)]
pub struct Invite {
    invite_key_wrapped_invite_data: DataEnvelope,
    invite_secret_wrapped_invite_key: SecretProtectedKeyEnvelope,
    invite_key_wrapped_organization_key: Option<SymmetricKeyEnvelope>,
    organization_key_wrapped_invite_key: EncString,
}

/// Wire format for [`Invite`]. This is what's serialized by serde (as base64-encoded CBOR).
#[derive(Serialize, Deserialize)]
struct InviteWire {
    invite_key_wrapped_invite_data: DataEnvelope,
    invite_secret_wrapped_invite_key: SecretProtectedKeyEnvelope,
    invite_key_wrapped_organization_key: Option<SymmetricKeyEnvelope>,
    organization_key_wrapped_invite_key: EncString,
}

impl From<&Invite> for InviteWire {
    fn from(invite: &Invite) -> Self {
        InviteWire {
            invite_key_wrapped_invite_data: invite.invite_key_wrapped_invite_data.clone(),
            invite_secret_wrapped_invite_key: invite.invite_secret_wrapped_invite_key.clone(),
            invite_key_wrapped_organization_key: invite.invite_key_wrapped_organization_key.clone(),
            organization_key_wrapped_invite_key: invite.organization_key_wrapped_invite_key.clone(),
        }
    }
}

impl From<&Invite> for String {
    fn from(invite: &Invite) -> Self {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&InviteWire::from(invite), &mut buf)
            .expect("CBOR serialization of Invite never fails");
        B64::from(buf).to_string()
    }
}

impl FromStr for Invite {
    type Err = InviteKeyBundleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = B64::try_from(s)
            .map_err(|_| InviteKeyBundleError::DecodingFailed)?
            .into_bytes();
        let data: InviteWire = ciborium::de::from_reader(bytes.as_slice())
            .map_err(|_| InviteKeyBundleError::DecodingFailed)?;
        Ok(Invite {
            invite_key_wrapped_invite_data: data.invite_key_wrapped_invite_data,
            invite_secret_wrapped_invite_key: data.invite_secret_wrapped_invite_key,
            invite_key_wrapped_organization_key: data.invite_key_wrapped_organization_key,
            organization_key_wrapped_invite_key: data.organization_key_wrapped_invite_key,
        })
    }
}

impl<'de> Deserialize<'de> for Invite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for Invite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

// Manually implemented to mirror the safe key-envelope primitives: it surfaces the wrapped fields
// without ever printing key material (each field's own `Debug` is key-material-safe).
impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field(
                "invite_key_wrapped_invite_data",
                &self.invite_key_wrapped_invite_data,
            )
            .field(
                "invite_secret_wrapped_invite_key",
                &self.invite_secret_wrapped_invite_key,
            )
            .field(
                "invite_key_wrapped_organization_key",
                &self.invite_key_wrapped_organization_key,
            )
            .field(
                "organization_key_wrapped_invite_key",
                &self.organization_key_wrapped_invite_key,
            )
            .finish()
    }
}

impl Invite {
    /// Recovers the invite key using the organization key
    pub fn invite_key_from_organization_key<Ids: KeySlotIds>(
        &self,
        organization_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, InviteKeyBundleError> {
        ctx.unwrap_symmetric_key(organization_key, &self.organization_key_wrapped_invite_key)
            .map_err(|_| InviteKeyBundleError::KeyUnsealingFailed)
    }

    /// Recovers the invite key from the invite secret
    pub fn invite_key_from_invite_secret<Ids: KeySlotIds>(
        &self,
        invite_secret: &InviteSecret,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, InviteKeyBundleError> {
        let secret = HighEntropySecret::from(invite_secret.clone());
        self.invite_secret_wrapped_invite_key
            .unseal(&secret, INVITE_SECRET_ENVELOPE_NAMESPACE, ctx)
            .map_err(|_| InviteKeyBundleError::KeyUnsealingFailed)
    }

    /// Unseals the `InviteDataV1` using an invite key
    fn unseal_invite_data<Ids: KeySlotIds>(
        &self,
        invite_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<InviteDataV1, InviteKeyBundleError> {
        let data: InviteData = self
            .invite_key_wrapped_invite_data
            .unseal(invite_key, ctx)
            .map_err(|_| InviteKeyBundleError::KeyUnsealingFailed)?;
        let InviteData::InviteDataV1(data) = data;
        Ok(data)
    }

    /// Recovers the [`InviteSecret`] using an invite key
    pub fn get_invite_secret<Ids: KeySlotIds>(
        &self,
        invite_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<InviteSecret, InviteKeyBundleError> {
        let data = self.unseal_invite_data(invite_key, ctx)?;
        Ok(InviteSecret(Zeroizing::new(data.invite_secret)))
    }

    /// Recovers the organization public-key thumbprint bound into the invite using an invite key
    pub fn get_public_key_thumbprint<Ids: KeySlotIds>(
        &self,
        invite_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<CoseKeyThumbprint, InviteKeyBundleError> {
        let data = self.unseal_invite_data(invite_key, ctx)?;
        Ok(CoseKeyThumbprint::from_bytes(data.public_key_thumbprint))
    }

    /// Whether confirmation is enabled on this invite, i.e. whether the organization key can be
    /// recovered from the invite key.
    pub fn supports_confirmation(&self) -> bool {
        self.invite_key_wrapped_organization_key.is_some()
    }

    /// Unseals the organization key using an invite key, storing it in the key store context and
    /// returning its id.
    pub fn unseal_organization_key<Ids: KeySlotIds>(
        &self,
        invite_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, InviteKeyBundleError> {
        self.invite_key_wrapped_organization_key
            .as_ref()
            .ok_or(InviteKeyBundleError::ConfirmationNotEnabled)?
            .unseal(invite_key, INVITE_ORG_KEY_ENVELOPE_NAMESPACE, ctx)
            .map_err(|_| InviteKeyBundleError::KeyUnsealingFailed)
    }

    /// Enables confirmatio
    pub fn enable_confirmation<Ids: KeySlotIds>(
        &mut self,
        organization_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<(), InviteKeyBundleError> {
        let invite_key = self.invite_key_from_organization_key(organization_key, ctx)?;
        let envelope = SymmetricKeyEnvelope::seal(
            organization_key,
            invite_key,
            INVITE_ORG_KEY_ENVELOPE_NAMESPACE,
            ctx,
        )
        .map_err(|_| InviteKeyBundleError::KeySealingFailed)?;
        self.invite_key_wrapped_organization_key = Some(envelope);
        Ok(())
    }

    /// Disables confirmation
    pub fn disable_confirmation(&mut self) {
        self.invite_key_wrapped_organization_key = None;
    }
}

/// A struct for holding the invite secret and the invite.
#[derive(Debug)]
pub struct InviteBundle {
    // The unencrypted invite secret. IMPORTANT: This must never be sent to the server.
    invite_secret: InviteSecret,
    // The cryptographic invite
    invite: Invite,
}

impl InviteBundle {
    /// Generates a brand new invite around a fresh AES-256-GCM invite key, binding it to the
    /// provided organization key and the organization's public-key thumbprint (see [`Invite`]).
    ///
    /// `wrapped_private_key` is the organization's private key wrapped with `organization_key`; the
    /// public-key thumbprint bound into the invite is derived from it.
    pub fn make_for_private_key<Ids: KeySlotIds>(
        organization_key: Ids::Symmetric,
        wrapped_private_key: &EncString,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Self, InviteKeyBundleError> {
        // Derive the organization public-key thumbprint from the wrapped private key.
        let private_key_id = ctx
            .unwrap_private_key(organization_key, wrapped_private_key)
            .map_err(|_| InviteKeyBundleError::InvalidPrivateKey)?;
        let thumbprint = ctx
            .get_public_key(private_key_id)
            .map_err(|_| InviteKeyBundleError::InvalidPrivateKey)?
            .thumbprint()
            .map_err(|_| InviteKeyBundleError::InvalidPrivateKey)?;

        // Generate the URL-fragment invite secret (goes in the invite link).
        let mut bytes = Zeroizing::new([0u8; INVITE_SECRET_LEN]);
        bitwarden_random::rng().fill_bytes(bytes.as_mut_slice());
        let invite_secret = InviteSecret(bytes);

        // Generate the AES-256-GCM invite key (the hub). It is used for exactly two AES-256-GCM
        // messages below (the invite-data DataEnvelope and the org-key SymmetricKeyEnvelope), each
        // with a fresh random nonce, so there is no nonce-reuse concern.
        let invite_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256Gcm);

        // Seal the invite data (thumbprint + a copy of the invite secret) with the invite key.
        let invite_data: InviteData = InviteDataV1 {
            public_key_thumbprint: *thumbprint.as_bytes(),
            invite_secret: *invite_secret.0,
        }
        .into();
        let invite_key_wrapped_invite_data =
            DataEnvelope::seal_with_provided_key(invite_data, invite_key, ctx)
                .map_err(|_| InviteKeyBundleError::KeySealingFailed)?;

        // Seal the invite key with the invite secret (invitee -> invite key direction).
        let secret = HighEntropySecret::from(invite_secret.clone());
        let invite_secret_wrapped_invite_key = SecretProtectedKeyEnvelope::seal(
            invite_key,
            &secret,
            INVITE_SECRET_ENVELOPE_NAMESPACE,
            ctx,
        )
        .map_err(|_| InviteKeyBundleError::KeySealingFailed)?;

        // Seal the organization key with the invite key (invite key -> organization key direction).
        // New invites are created with confirmation enabled; callers can disable it afterwards via
        // `Invite::disable_confirmation`.
        let invite_key_wrapped_organization_key = Some(
            SymmetricKeyEnvelope::seal(
                organization_key,
                invite_key,
                INVITE_ORG_KEY_ENVELOPE_NAMESPACE,
                ctx,
            )
            .map_err(|_| InviteKeyBundleError::KeySealingFailed)?,
        );

        // Wrap the invite key with the organization key (organization key -> invite key direction).
        let organization_key_wrapped_invite_key = ctx
            .wrap_symmetric_key(organization_key, invite_key)
            .map_err(|_| InviteKeyBundleError::KeySealingFailed)?;

        Ok(Self {
            invite_secret,
            invite: Invite {
                invite_key_wrapped_invite_data,
                invite_secret_wrapped_invite_key,
                invite_key_wrapped_organization_key,
                organization_key_wrapped_invite_key,
            },
        })
    }

    /// Get the raw invite secret.
    /// CRITICAL: this data MUST NOT be sent to the server
    ///
    /// This can be base64url encoded for URL use only:
    /// ```ignore
    /// let secret: &InviteSecret = bundle.dangerous_get_raw_invite_secret();
    /// let secret_bytes: String = String::from(secret);
    /// ```
    pub fn dangerous_get_raw_invite_secret(&self) -> &InviteSecret {
        &self.invite_secret
    }

    /// Gets the invite (safe to send to the server).
    pub fn get_envelope(&self) -> &Invite {
        &self.invite
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{
        CoseKeyThumbprint, CoseKeyThumbprintExt, EncString, KeyStore, KeyStoreContext,
        PublicKeyEncryptionAlgorithm, SymmetricCryptoKey, key_slot_ids,
    };
    use bitwarden_encoding::{B64, B64Url};

    use crate::invite_key_bundle::{Invite, InviteBundle, InviteKeyBundleError, InviteSecret};

    /// Makes an organization private key in `ctx`, wraps it with `organization_key`, and returns
    /// the wrapped private key together with the thumbprint of its public key (as
    /// `make_for_private_key` expects and derives).
    fn org_wrapped_private_key(
        organization_key: TestSymmKey,
        ctx: &mut KeyStoreContext<'_, TestIds>,
    ) -> (EncString, CoseKeyThumbprint) {
        let private_key_id = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let thumbprint = ctx
            .get_public_key(private_key_id)
            .unwrap()
            .thumbprint()
            .unwrap();
        let wrapped = ctx
            .wrap_private_key(organization_key, private_key_id)
            .unwrap();
        (wrapped, thumbprint)
    }

    #[test]
    fn test_basic_invitation_bundle() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();
        let (wrapped_private_key, _) = org_wrapped_private_key(TestSymmKey::Organization, &mut ctx);

        let bundle1 = InviteBundle::make_for_private_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();
        let bundle2 = InviteBundle::make_for_private_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();

        assert_ne!(bundle1.invite_secret, bundle2.invite_secret);
    }

    #[test]
    fn test_admin_recovers_invite_secret() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();
        let (wrapped_private_key, _) = org_wrapped_private_key(TestSymmKey::Organization, &mut ctx);

        let bundle = InviteBundle::make_for_private_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();

        let invite = bundle.get_envelope();
        let invite_key = invite
            .invite_key_from_organization_key(TestSymmKey::Organization, &mut ctx)
            .unwrap();
        let recovered = invite.get_invite_secret(invite_key, &mut ctx).unwrap();

        assert_eq!(bundle.dangerous_get_raw_invite_secret(), &recovered);
    }

    #[test]
    fn test_admin_recovers_thumbprint() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();
        let (wrapped_private_key, thumbprint) =
            org_wrapped_private_key(TestSymmKey::Organization, &mut ctx);

        let bundle = InviteBundle::make_for_private_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();

        let invite = bundle.get_envelope();
        let invite_key = invite
            .invite_key_from_organization_key(TestSymmKey::Organization, &mut ctx)
            .unwrap();
        let recovered = invite
            .get_public_key_thumbprint(invite_key, &mut ctx)
            .unwrap();

        assert_eq!(recovered, thumbprint);
    }

    #[test]
    fn test_invitee_recovers_organization_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();
        let (wrapped_private_key, _) = org_wrapped_private_key(TestSymmKey::Organization, &mut ctx);

        let bundle = InviteBundle::make_for_private_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();

        // Using only the raw invite secret, an invitee can recover the invite key and then the
        // organization key.
        let invite = bundle.get_envelope();
        let invite_key = invite
            .invite_key_from_invite_secret(bundle.dangerous_get_raw_invite_secret(), &mut ctx)
            .unwrap();
        let recovered_org_key_id = invite
            .unseal_organization_key(invite_key, &mut ctx)
            .unwrap();

        #[allow(deprecated)]
        let recovered_org_key = ctx
            .dangerous_get_symmetric_key(recovered_org_key_id)
            .unwrap()
            .clone();
        #[allow(deprecated)]
        let org_key = ctx
            .dangerous_get_symmetric_key(TestSymmKey::Organization)
            .unwrap()
            .clone();
        assert_eq!(recovered_org_key, org_key);
    }

    #[test]
    fn test_confirmation_toggle() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();
        let (wrapped_private_key, _) = org_wrapped_private_key(TestSymmKey::Organization, &mut ctx);

        let bundle = InviteBundle::make_for_private_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();
        let mut invite = bundle.get_envelope().clone();

        // New invites are created with confirmation enabled.
        assert!(invite.supports_confirmation());

        // Disabling confirmation removes the org-key envelope, so an invitee can no longer recover
        // the organization key.
        invite.disable_confirmation();
        assert!(!invite.supports_confirmation());
        let invite_key = invite
            .invite_key_from_invite_secret(bundle.dangerous_get_raw_invite_secret(), &mut ctx)
            .unwrap();
        assert!(matches!(
            invite.unseal_organization_key(invite_key, &mut ctx),
            Err(InviteKeyBundleError::ConfirmationNotEnabled)
        ));

        // Re-enabling confirmation restores the invitee's ability to recover the organization key.
        invite
            .enable_confirmation(TestSymmKey::Organization, &mut ctx)
            .unwrap();
        assert!(invite.supports_confirmation());
        let invite_key = invite
            .invite_key_from_invite_secret(bundle.dangerous_get_raw_invite_secret(), &mut ctx)
            .unwrap();
        let recovered_org_key_id = invite
            .unseal_organization_key(invite_key, &mut ctx)
            .unwrap();
        #[allow(deprecated)]
        {
            let recovered = ctx
                .dangerous_get_symmetric_key(recovered_org_key_id)
                .unwrap()
                .clone();
            let org_key = ctx
                .dangerous_get_symmetric_key(TestSymmKey::Organization)
                .unwrap()
                .clone();
            assert_eq!(recovered, org_key);
        }
    }

    #[test]
    fn test_invite_string_round_trip() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();
        let (wrapped_private_key, _) = org_wrapped_private_key(TestSymmKey::Organization, &mut ctx);

        let bundle = InviteBundle::make_for_private_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();
        let invite = bundle.get_envelope();

        let encoded = String::from(invite);
        let decoded: Invite = encoded.parse().unwrap();
        assert_eq!(String::from(&decoded), encoded);

        // The decoded invite still recovers the invite secret.
        let invite_key = decoded
            .invite_key_from_organization_key(TestSymmKey::Organization, &mut ctx)
            .unwrap();
        let recovered = decoded.get_invite_secret(invite_key, &mut ctx).unwrap();
        assert_eq!(bundle.dangerous_get_raw_invite_secret(), &recovered);

        // The custom serde impls delegate to the string round-trip.
        let json = serde_json::to_string(invite).unwrap();
        let from_json: Invite = serde_json::from_str(&json).unwrap();
        assert_eq!(String::from(&from_json), encoded);
    }

    #[test]
    fn test_into_base64_url() {
        let data: [u8; 32] = *b"+/=Hello, World!AAAAAAAAAAAAAAAA";
        let secret = InviteSecret(zeroize::Zeroizing::new(data));

        let encoded = String::from(&secret);

        assert_eq!(encoded, "Ky89SGVsbG8sIFdvcmxkIUFBQUFBQUFBQUFBQUFBQUE");
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));

        let decoded = B64Url::try_from(encoded.as_str()).unwrap();
        assert_eq!(decoded.as_bytes(), data);

        // Round-trips back to the same invite secret.
        let reparsed: InviteSecret = encoded.parse().unwrap();
        assert_eq!(reparsed, secret);
    }

    // Test vectors captured from `generate_test_vectors`. These freeze a real invite so that
    // backward compatibility (old data must remain decryptable) is verified by
    // `test_invite_test_vector`.
    const TEST_VECTOR_ORG_KEY: &str =
        "KGP9Nc2/91w+42Z9VzY0m7h18avuZcq4ICM8Rhdc3BD92LbWS2TQkVBzavvUM684WKXiC22NJi2EwaiDW4YTAA==";
    const TEST_VECTOR_INVITE: &str = "pHgeaW52aXRlX2tleV93cmFwcGVkX2ludml0ZV9kYXRheQGEZzFoSHBRRURBM2dqWVhCd2JHbGpZWFJwYjI0dmVDNWlhWFIzWVhKa1pXNHVZMkp2Y2kxd1lXUmtaV1FFVU8yS1A5c3pkbVF6MDlQTm1HeVZOOWc2QUFFNGdRSTZBQUU0Z0FLaEJVeUJjVUJCWCtScWk5UlM1KzlZeG8rZmpkdHJQemRVQ0FUSitGaTZtQ2puNCtYUmdwN1FEdHlLOXVjQlJiR2hKb2tHcWxqQko0RXhOOENnSEhwUGc0U0JqcGhOVE95TElZOXZ6bEZRcGV3djR3a3FaeUZkNGh0TXk4L3M0R3R0K1hkRjEzR1EvKzRMcFc0b04yOHRDdDNDcTNxbExUUGZaL09VNm1zTUlRaGhIZm1NWXI3eWwra0FiU09KQkwwek40bGNwbXRGZGtEYkRSRkdqdUx5YkRONHJ6cjRBTmdhaUJkMkZ6Q09UdjRRWGdLek5oazVWMEdiM3lrSjhlcGpJSUhRM3cyYWdIRXJJRmtoNE13R1ZzN2NXVDNka3c9PXggaW52aXRlX3NlY3JldF93cmFwcGVkX2ludml0ZV9rZXl49GhGZ29wUUVEQXhobE9nQUJGVnhRN1lvLzJ6TjJaRFBUMDgyWWJKVTMyRG9BQVRpQkJqb0FBVGlBQWFFRlRNZlJWRXFWUWxWMVlFQ1B0MWhRTTVyVVZjVVRmQkNYbzJvVFJkNW9URnRZblNvNWVpakh1UzhJcjlhT3daay83Y2dTeVhWSDh6NWl2QmYxVitqMitBT3B5dVBLTTQ4NGJva3owSmJEUW9KK2REQzNFMFVMQnVTVXFsbm5TcXVCZzBDaUFTa3pXQ0FUMEk1NC9OSFBnNFRQWjB5RjBsNlk3M3FNbG1XYVg2RThBdU1UcHBvQTdQWT14I2ludml0ZV9rZXlfd3JhcHBlZF9vcmdhbml6YXRpb25fa2V5eORnMWhHcFFFREEzZ2lZWEJ3YkdsallYUnBiMjR2ZUM1aWFYUjNZWEprWlc0dWJHVm5ZV041TFd0bGVRUlE3WW8vMnpOMlpEUFQwODJZYkpVMzJEb0FBVGlCQXpvQUFUaUFBcUVGVFBWSzVFUEVYbXVwZ29mMkRWaFF2Mlg2QkdKcCthb0pocnZjbTRxaUJMRTJHMHZhbzE3SjhXOEQxRGJvM0lpZWFzSXRsNzJwenloY21uMWh4WmM4c0k3RThIZGlRSXF6N1lSc2lQdlpUSEVJSHZqeUFrTG8reE10QW1xbUZacz14I29yZ2FuaXphdGlvbl9rZXlfd3JhcHBlZF9pbnZpdGVfa2V5eLQyLkNsM2JGTzFETENndzJ3elJ3bmtSa2c9PXw5aDEwbStqb1hmcE5pTHpnRS8yclBqaituS3JWWVl1bXBBQ2dEa2h6RUEyNVo3WjNUVTJuYnNLN2J5SWZWV0NkQ1lrQTFlQk5BNk9WN3NpcGhXWmVzRmpoVTYyT0Voc0FzOUo3K2xxODVXMD18Qk14TW52Y1JtNldSV0FveUppTnRjTjZaQkpSRE82YkFPTjZhaVhHbExBYz0=";
    const TEST_VECTOR_INVITE_SECRET: &str = "CptXaIhmgvJ7YMNA9h9DDe13ad7ayxGPPGxik-fNWls";

    #[test]
    #[ignore = "Manual test to generate test vectors"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let org_key =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_ORG_KEY).unwrap()).unwrap();
        let org_key_id = ctx.add_local_symmetric_key(org_key);
        let (wrapped_private_key, _) = org_wrapped_private_key(org_key_id, &mut ctx);

        let bundle =
            InviteBundle::make_for_private_key(org_key_id, &wrapped_private_key, &mut ctx).unwrap();

        println!(
            "const TEST_VECTOR_INVITE: &str = \"{}\";",
            String::from(bundle.get_envelope())
        );
        println!(
            "const TEST_VECTOR_INVITE_SECRET: &str = \"{}\";",
            String::from(bundle.dangerous_get_raw_invite_secret())
        );
    }

    #[test]
    fn test_invite_test_vector() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let org_key =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_ORG_KEY).unwrap()).unwrap();
        let org_key_id = ctx.add_local_symmetric_key(org_key);

        let invite: Invite = TEST_VECTOR_INVITE.parse().unwrap();
        let invite_key = invite
            .invite_key_from_organization_key(org_key_id, &mut ctx)
            .unwrap();
        let recovered = invite.get_invite_secret(invite_key, &mut ctx).unwrap();

        assert_eq!(String::from(&recovered), TEST_VECTOR_INVITE_SECRET);
    }

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_debug() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(org_key_id, TestSymmKey::Organization)
            .unwrap();
        let (wrapped_private_key, _) = org_wrapped_private_key(TestSymmKey::Organization, &mut ctx);

        let bundle = InviteBundle::make_for_private_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();
        // Exercises both the `InviteSecret` and `Invite` `Debug` impls.
        println!("{bundle:?}");
    }

    key_slot_ids! {
        #[symmetric]
        pub enum TestSymmKey {
            Organization,
            #[local]
            Local(LocalId),
        }

        #[private]
        pub enum TestPrivateKey {
            A(u8),
            B,
            #[local]
            C(LocalId),
        }

        #[signing]
        pub enum TestSigningKey {
            A(u8),
            B,
            #[local]
            C(LocalId),
        }

       pub TestIds => TestSymmKey, TestPrivateKey, TestSigningKey;
    }
}
