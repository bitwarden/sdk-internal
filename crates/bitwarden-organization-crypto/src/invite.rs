//! Cryptographic organization invites
//!
//! An invite is built around an XAES-256-GCM **invite key** that acts as the hub tying every sealed
//! object together. Two independent secrets can recover the invite key (the invite secret from the
//! link, or the organization key held by admins), and from the invite key everything else — the
//! invite data and, when confirmation is enabled, the organization key — can be unsealed:
//!
//! ```text
//! InviteSecret -> SecretProtectedKeyEnvelope -> InviteKey -> SymmetricKeyEnvelope -> InviteDataCEK
//!                                                ^     |                                   |
//!                                                |     |               DataEnvelope --------+
//!                                                |     |                    +-> InviteSecret
//!                                                |     |                    +-> OrgPubKeyPrint
//! OrganizationKey -> EncString ------------------+     +-> SymmetricKeyEnvelope -> OrganizationKey
//! ```
//!
//! - `InviteSecret -> SecretProtectedKeyEnvelope -> InviteKey` (`invite_secret_sealed_invite_key`):
//!   the invite key sealed with the high-entropy invite secret, so an invitee holding only the
//!   secret from the link recovers the invite key.
//! - `OrganizationKey -> EncString -> InviteKey` (`organization_key_sealed_invite_key`): the invite
//!   key sealed with the organization key, so anyone holding the organization key recovers the
//!   invite key (and thus the invite data).
//! - `InviteKey -> SymmetricKeyEnvelope -> InviteDataCEK -> DataEnvelope -> InviteSecret +
//!   OrgPubKeyPrint` (`invite_key_sealed_invite_data_cek` + `sealed_invite_data`): the
//!   `InviteDataV1` is sealed under its own content-encryption key (CEK), and that CEK is sealed
//!   with the invite key. The data binds the organization public-key thumbprint and a copy of the
//!   invite secret (so the invite link can be reconstructed from the invite key).
//! - `InviteKey -> SymmetricKeyEnvelope -> OrganizationKey` (`invite_key_sealed_organization_key`):
//!   the organization key sealed with the invite key, so a redeeming invitee can recover the
//!   organization key. It is present if and exactly if confirmation is enabled for the invite.

use std::str::FromStr;

use bitwarden_crypto::{
    CoseKeyThumbprint, CoseKeyThumbprintExt, EncString, KeySlotIds, KeyStoreContext,
    generate_versioned_sealable,
    safe::{
        DataEnvelope, DataEnvelopeNamespace, HighEntropySecret, HighEntropySecretSource,
        KeyEncryptionKey, SealableData, SealableVersionedData, SecretProtectedKeyEnvelope,
        SecretProtectedKeyEnvelopeNamespace, SymmetricKeyEnvelope, SymmetricKeyEnvelopeNamespace,
    },
};
use bitwarden_encoding::{B64Url, FromStrVisitor};
use bitwarden_sensitive_value::{Sensitive, SensitiveSlice};
use rand::Rng;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use thiserror::Error;
use zeroize::Zeroizing;

/// Length, in bytes, of the raw invite secret. 32 bytes provides 256 bits of entropy, which is why
/// the invite secret is safe to use directly as a [`HighEntropySecret`].
const INVITE_SECRET_LEN: usize = 32;

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

/// The invite secret: 32 random, high-entropy bytes carried in the invite link.
///
/// CRITICAL: This must never be sent to the server.
#[derive(Clone)]
pub struct InviteSecret(Zeroizing<[u8; INVITE_SECRET_LEN]>);

impl InviteSecret {
    /// Generates a fresh invite secret: 32 random, high-entropy bytes drawn from the SDK CSPRNG.
    fn make() -> Self {
        let mut bytes = Zeroizing::new([0u8; INVITE_SECRET_LEN]);
        bitwarden_random::rng().fill_bytes(bytes.as_mut_slice());
        InviteSecret(bytes)
    }
}

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

/// Cryptographic invite for an organization, built around an XAES-256-GCM invite key that acts as
/// the hub tying everything together. See the module-level docs for the overall diagram.
#[derive(Clone, Serialize, Deserialize)]
pub struct Invite {
    /// The `InviteData` (org public-key thumbprint + invite secret) sealed with its own
    /// content-encryption key (CEK).
    sealed_invite_data: DataEnvelope,
    /// The invite-data content-encryption key sealed with the invite key, so a holder of the
    /// invite key can recover the CEK and open [`Self::sealed_invite_data`].
    invite_key_sealed_invite_data_cek: SymmetricKeyEnvelope,
    /// The invite key sealed with the high-entropy invite secret, letting an invitee (who holds
    /// only the invite secret from the link) recover the invite key.
    invite_secret_sealed_invite_key: SecretProtectedKeyEnvelope,
    /// The organization key sealed with the invite key, letting a redeeming invitee recover the
    /// organization key once they hold the invite key. This is **optional**: its presence is what
    /// "confirmation" means. When confirmation is enabled the invitee can self-confirm by
    /// recovering the organization key; when disabled, this field is absent and an admin must
    /// confirm the invitee out of band.
    invite_key_sealed_organization_key: Option<SymmetricKeyEnvelope>,
    /// The invite key sealed with the organization key, letting anyone holding the organization
    /// key recover the invite key (and thus the invite data).
    organization_key_sealed_invite_key: EncString,
}

impl From<&Invite> for String {
    fn from(invite: &Invite) -> Self {
        serde_json::to_string(invite).expect("JSON serialization of Invite never fails")
    }
}

impl FromStr for Invite {
    type Err = InviteKeyBundleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map_err(|_| InviteKeyBundleError::DecodingFailed)
    }
}

// Manually implemented to mirror the safe key-envelope primitives: it surfaces the sealed fields
// without ever printing key material (each field's own `Debug` is key-material-safe).
impl std::fmt::Debug for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invite")
            .field("sealed_invite_data", &self.sealed_invite_data)
            .field(
                "invite_key_sealed_invite_data_cek",
                &self.invite_key_sealed_invite_data_cek,
            )
            .field(
                "invite_secret_sealed_invite_key",
                &self.invite_secret_sealed_invite_key,
            )
            .field(
                "invite_key_sealed_organization_key",
                &self.invite_key_sealed_organization_key,
            )
            .field(
                "organization_key_sealed_invite_key",
                &self.organization_key_sealed_invite_key,
            )
            .finish()
    }
}

impl Invite {
    /// Recovers the invite key using the organization key
    pub fn unseal_invite_key_with_organization_key<Ids: KeySlotIds>(
        &self,
        organization_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, InviteKeyBundleError> {
        ctx.unwrap_symmetric_key(organization_key, &self.organization_key_sealed_invite_key)
            .map_err(|_| InviteKeyBundleError::KeyUnsealingFailed)
    }

    /// Recovers the invite key from the invite secret
    pub fn unseal_invite_key_with_invite_secret<Ids: KeySlotIds>(
        &self,
        invite_secret: &InviteSecret,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, InviteKeyBundleError> {
        let secret = HighEntropySecret::from(invite_secret.clone());
        self.invite_secret_sealed_invite_key
            .unseal(
                &secret,
                SecretProtectedKeyEnvelopeNamespace::OrganizationInvite,
                ctx,
            )
            .map_err(|_| InviteKeyBundleError::KeyUnsealingFailed)
    }

    /// Unseals the `InviteDataV1` using an invite key
    fn unseal_invite_data<Ids: KeySlotIds>(
        &self,
        invite_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<InviteDataV1, InviteKeyBundleError> {
        // Recover the invite-data CEK by unsealing it with the invite key, then open the data.
        let cek = self
            .invite_key_sealed_invite_data_cek
            .unseal(
                invite_key,
                SymmetricKeyEnvelopeNamespace::OrganizationInvite,
                ctx,
            )
            .map_err(|_| InviteKeyBundleError::KeyUnsealingFailed)?;
        let data: InviteData = self
            .sealed_invite_data
            .unseal(cek, ctx)
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
        self.invite_key_sealed_organization_key.is_some()
    }

    /// Unseals the organization key using an invite key, storing it in the key store context and
    /// returning its id.
    pub fn unseal_organization_key<Ids: KeySlotIds>(
        &self,
        invite_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, InviteKeyBundleError> {
        self.invite_key_sealed_organization_key
            .as_ref()
            .ok_or(InviteKeyBundleError::ConfirmationNotEnabled)?
            .unseal(
                invite_key,
                SymmetricKeyEnvelopeNamespace::OrganizationInvite,
                ctx,
            )
            .map_err(|_| InviteKeyBundleError::KeyUnsealingFailed)
    }

    /// Enables confirmation
    pub fn enable_confirmation<Ids: KeySlotIds>(
        &mut self,
        organization_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<(), InviteKeyBundleError> {
        let invite_key = self.unseal_invite_key_with_organization_key(organization_key, ctx)?;
        let envelope = SymmetricKeyEnvelope::seal(
            organization_key,
            invite_key,
            SymmetricKeyEnvelopeNamespace::OrganizationInvite,
            ctx,
        )
        .map_err(|_| InviteKeyBundleError::KeySealingFailed)?;
        self.invite_key_sealed_organization_key = Some(envelope);
        Ok(())
    }

    /// Disables confirmation
    pub fn disable_confirmation(&mut self) {
        self.invite_key_sealed_organization_key = None;
    }

    /// Generates a brand new invite around a new invite key. The invite is sealed for the
    /// provided organization key and bound to the organization's public-key thumbprint (see
    /// [`Invite`]).
    ///
    /// `wrapped_organization_private_key` is the organization's private key wrapped with
    /// `organization_key`; the public-key thumbprint bound into the invite is derived from it.
    ///
    /// Returns the raw [`InviteSecret`] (which MUST NOT be sent to the server) together with the
    /// server-safe [`Invite`].
    pub fn make_for_private_key<Ids: KeySlotIds>(
        organization_key: Ids::Symmetric,
        wrapped_organization_private_key: &EncString,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<(InviteSecret, Invite), InviteKeyBundleError> {
        // Derive the organization public-key thumbprint from the wrapped private key.
        let private_key_id = ctx
            .unwrap_private_key(organization_key, wrapped_organization_private_key)
            .map_err(|_| InviteKeyBundleError::InvalidPrivateKey)?;
        let thumbprint = ctx
            .get_public_key(private_key_id)
            .map_err(|_| InviteKeyBundleError::InvalidPrivateKey)?
            .thumbprint()
            .map_err(|_| InviteKeyBundleError::InvalidPrivateKey)?;

        let invite_secret = InviteSecret::make();
        let invite_key = KeyEncryptionKey::make(ctx);

        // Seal the invite data (thumbprint + a copy of the invite secret) under a fresh
        // content-encryption key (CEK), then seal that CEK with the invite key so a holder of the
        // invite key can open the data.
        let invite_data: InviteData = InviteDataV1 {
            public_key_thumbprint: *thumbprint.as_bytes(),
            invite_secret: *invite_secret.0,
        }
        .into();
        let (sealed_invite_data, invite_data_cek) = DataEnvelope::seal(invite_data, ctx)
            .map_err(|_| InviteKeyBundleError::KeySealingFailed)?;
        let invite_key_sealed_invite_data_cek = SymmetricKeyEnvelope::seal(
            invite_data_cek,
            invite_key,
            SymmetricKeyEnvelopeNamespace::OrganizationInvite,
            ctx,
        )
        .map_err(|_| InviteKeyBundleError::KeySealingFailed)?;

        // Seal the invite key with the invite secret (invitee -> invite key direction).
        let secret = HighEntropySecret::from(invite_secret.clone());
        let invite_secret_sealed_invite_key = SecretProtectedKeyEnvelope::seal(
            invite_key,
            &secret,
            SecretProtectedKeyEnvelopeNamespace::OrganizationInvite,
            ctx,
        )
        .map_err(|_| InviteKeyBundleError::KeySealingFailed)?;

        // Seal the organization key with the invite key (invite key -> organization key direction).
        // New invites are created with confirmation enabled; callers can disable it afterwards via
        // `Invite::disable_confirmation`.
        let invite_key_sealed_organization_key = Some(
            SymmetricKeyEnvelope::seal(
                organization_key,
                invite_key,
                SymmetricKeyEnvelopeNamespace::OrganizationInvite,
                ctx,
            )
            .map_err(|_| InviteKeyBundleError::KeySealingFailed)?,
        );

        // Seal the invite key with the organization key (organization key -> invite key direction).
        let organization_key_sealed_invite_key = ctx
            .wrap_symmetric_key(organization_key, invite_key)
            .map_err(|_| InviteKeyBundleError::KeySealingFailed)?;

        Ok((
            invite_secret,
            Invite {
                sealed_invite_data,
                invite_key_sealed_invite_data_cek,
                invite_secret_sealed_invite_key,
                invite_key_sealed_organization_key,
                organization_key_sealed_invite_key,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{
        CoseKeyThumbprintExt, EncString, KeyStore, KeyStoreContext, PublicKeyEncryptionAlgorithm,
        SymmetricCryptoKey, key_slot_ids,
    };
    use bitwarden_encoding::{B64, B64Url};

    use crate::invite::{Invite, InviteKeyBundleError, InviteSecret};

    // Test vectors captured from `generate_test_vectors`. They freeze a real organization key, the
    // organization private key wrapped with it, and an invite, so backward compatibility (old data
    // must remain decryptable) is verified by `test_invite_test_vector`.
    const TEST_VECTOR_ORG_KEY: &str =
        "KGP9Nc2/91w+42Z9VzY0m7h18avuZcq4ICM8Rhdc3BD92LbWS2TQkVBzavvUM684WKXiC22NJi2EwaiDW4YTAA==";
    const TEST_VECTOR_WRAPPED_PRIVATE_KEY: &str = "2.bi9TWF/zrujUg1y+v8ECtQ==|kEMkuRt42j65YZnPEc4bLOT0/WDZwWSNJNGlUMdr/LRF3qi/vCnZ7eT0+7MruTccmyoAjKmsXdoBcufrOdPBUguFQn1LQMGqHqCyyB3SIijOlLyOOmxWYqoLUjihy8o8URGWjrAGWZnkeYWHTlFZP09Fag2xCwiQ/qS32Q+qTGGHDs0FiwjplcPkW9knlmgCXbuyPqDnEYoa0Qs/CC1hUCzFFrWs7QkE+5eLaNHxuBPpsrY6y795kEu9ve38F3piY9b6lQpc/iPGv8Zfh1isI7Mpy1zMwntXGSHjUOy17nPxCqkgYufuNGnwGNwsGjkLAl7e7bD39SYfEpTDaRUgmTl8UrZDx274e6Um1LLvokf3HiL1tboJ9/TW8IiMuAdrb3PLTH6Sep8lqZ3WhNADfMMJle9kCojHp6XSB14in1JqP0636exYeJu+FhUC1TfrthuQN2QDQ8LAvgZR7YvzkTJX3Sc5jP7m/yCmCbHhIqIAaGqJsRwAee0EMsKcALz3/akVoyjHU2LHD3dzQnyMyszyRNYViBNYAM9qBN2DqwWRDOtM171xNVJcTFsAh4mBSLiLOlDsXqLqHVKu2VJNE1XhTQ5Szubqefa/Or7nfxXcxDvivqZ7d5NfDFEskUMqh5yq1KoLK0oK5c+KvY/COIZr/kct+qtfZsXo3w5xJnPOqrAKGm+9CF4OINpLM8Z3csdZf9l5XjlmO1kIuBbquQZ0EZCHzD/GEfXRGB8BEkugdTfpnTDtmmuAJXkIY6t6e6pRUU9u4/sl+U7Iuh22fOA59SuQOElr5Lxre+hQBrRfJS3tSMEtMjYhVmltrngH+SLRxMxH/evbe2uvNaaxlFJe6EK1vqchyTX6nM8Z+2Yjb5pOAzrKQYqwwmVys9IHfjXhybqv10gFpDXBE/eq8u9xs9LbQQ03EbveQUtqdh/ms8SxLOQA9Sm9JwHEL0Zni+8NdAa5orDYzOi53bQLgrs+uUldgB/KOW2goTnKGm4YTbMAXEbum8pST8EXB9jNDXyofyN8IQUoLRvVkEgzbSPBS1sYpkkKdLZy3ojOCKnMnHXIVtzJojFckiutbj6d927X5w51E/RDMoAdylGRVKnmqLKysFRqL+pZK8Cyo+ECr7notG8kr7pVnofzigjKZS9qkRmqEa9bju1GgI20g4cxro8/0O0XnU1o0Mx46qH3niORY59i5bdMwaDS6H2c6+rmf9bIFwwgyAZvHlVdcGNoBGPR3ZXHThwI1OmWSslLWVW0IaS4utB1jL4zvHPCqh/ButA8HeRmU/NYSfaqb9YXyzn+C7ED15MWXkYmZzeE38HHxhqs12+oj+WFcg4d5/e2UcccuVi36SWhA0xWk8Kk2D6e1Pz1lmaw20vpb0eUq4AS5ZnMmWTEiKORFeGNTIROq9vuPuitLrREedu9PGjf5aeKcNqlq2nr7fOaxyi2ocKs7pLqVBUH1G7zHpCo3Rt1+o18guXFHT56vQFfkzoUNXiS6TRM4Mkl3s0TyGgBhxZkNJleTI6y4xhfH1iathBnLcfelLbxZhDB1wh3RXowS32jpM/J4pSUuNEmSLSqRQtRJY41BG00nYY02qEbakkgk6pS6a0/CWphyLfHAzUWbabOhqR1iPN9/ZiecjI=|eoklmBw+LYy2NNwjLOuA4+szKH5SzLGPlrhIJ/vfmW4=";
    const TEST_VECTOR_INVITE: &str = r#"{"sealed_invite_data":"g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUPw60HtcnAwO6kRKd7MnQz86AAE4gQI6AAE4gAKhBUz+fzObmLDLKRDeBJJYxX9qAxhXIe1Ri1CJw3ojv7WUEwBpVWeMEGTK7HHbp9WnTDjK849psMx6EOpQ7B/BYGiO28Zn0tjtQ85zwShii4FRK39mtJFE8XxV46hxW9+LlH6EPt4yfzHVkTNZ3vgOiSXcs6zyKXIhQaz6yh8eyA653m4DJEHV00JjdQ/jSfTEfyDf6LiflGntDZ7gSYlQMRxuS71yVP9Mgm79yFY4aIw703G/HUjvIEt4XlWCLzvaLDmegpDz9z4eQCVk8v8JM1fS7BsA","invite_key_sealed_invite_data_cek":"g1g+pgE6AAEReQMYZQRQ7raDdes1HnAgiuiZWXyS9ToAARVcUPw60HtcnAwO6kRKd7MnQz86AAE4gQM6AAE4gAKhBVgYvxSL4XPZLwEXHPnEWweqeeKjyH9r85/ZWE3rsZy1MLmzkFOCJa8a0o20b1P3IH6c5NYtT3v1a50+X0GmgDKiMf/omjhwRRQ7ua6wK0O2JBlhM4JIE8jmtsyMd46mFDbURK1kGRvl7Q==","invite_secret_sealed_invite_key":"hFgopQEDAxhlOgABFVxQ7raDdes1HnAgiuiZWXyS9ToAATiBBjoAATiAAaEFTJvCToVTNSe1uWbD5FhUf061kAAj1sMGWjJ8IWPV2e2xk5Z+ownZ1RqUXG2jv9h2vnsEFZ2yglvKaSCGTsOuvOXv0ESwQk6eUtFAaZjxV/Rajyuu6YgEa712Tfb9Jz13QLGngYNAogEpM1gg1MsuVokUsK8WkqggHRdJ4jvzFsbN/bP4g0l+j6f97qb2","invite_key_sealed_organization_key":"g1hKpQE6AAEReQN4ImFwcGxpY2F0aW9uL3guYml0d2FyZGVuLmxlZ2FjeS1rZXkEUO62g3XrNR5wIIromVl8kvU6AAE4gQM6AAE4gAKhBVgYoth3hg+yUTLXF4ksaeT42IWGKuTv27B4WFAKV8Z7uKGZNHOONGgZQLbQMozgYX9tseuet413M314W0sV3cBKZIRSEZfj3NvHU8tE/6b2oGxPQIPKP3Tyhl84zhI4uG+Mo5WKkvtdPonD0A==","organization_key_sealed_invite_key":"2.XjZXnAwXK/cXCmHNgCPQzw==|WEGa37JPdNWVnMPWlfinyvZdXpMW8kpTBypXPWf/abbG4/+6vp/WJQmVlkVEflEkuZwjKWSkMWJPcACGBoabeBHgzqpkSYf3kyQb7VhePHQ=|kZLDCLGm1nCJhlVuNahFiZOecy5tKG2fXGCNZZzbDjk="}"#;
    const TEST_VECTOR_INVITE_SECRET: &str = "Ttas45_CvZi1yoFJ3bMCHx0DAAGGxDi-1BhHCutwDjI";

    /// Loads the const `TEST_VECTOR_ORG_KEY` into the `Organization` slot and returns the parsed
    /// const wrapped organization private key. Sharing fixed vectors keeps tests deterministic and
    /// avoids generating a fresh RSA key on every run.
    fn load_test_vectors(ctx: &mut KeyStoreContext<'_, TestIds>) -> EncString {
        let org_key =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_ORG_KEY).unwrap()).unwrap();
        let local_org_key_id = ctx.add_local_symmetric_key(org_key);
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();
        TEST_VECTOR_WRAPPED_PRIVATE_KEY.parse().unwrap()
    }

    #[test]
    fn test_basic_invitation_bundle() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);

        let (secret1, _) =
            Invite::make_for_private_key(TestSymmKey::Organization, &wrapped_private_key, &mut ctx)
                .unwrap();
        let (secret2, _) =
            Invite::make_for_private_key(TestSymmKey::Organization, &wrapped_private_key, &mut ctx)
                .unwrap();

        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_admin_recovers_invite_secret() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);

        let (invite_secret, invite) =
            Invite::make_for_private_key(TestSymmKey::Organization, &wrapped_private_key, &mut ctx)
                .unwrap();

        let invite_key = invite
            .unseal_invite_key_with_organization_key(TestSymmKey::Organization, &mut ctx)
            .unwrap();
        let recovered = invite.get_invite_secret(invite_key, &mut ctx).unwrap();

        assert_eq!(invite_secret, recovered);
    }

    #[test]
    fn test_admin_recovers_thumbprint() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);

        // The expected thumbprint is derived from the same wrapped private key that
        // `make_for_private_key` binds into the invite.
        let private_key_id = ctx
            .unwrap_private_key(TestSymmKey::Organization, &wrapped_private_key)
            .unwrap();
        let expected = ctx
            .get_public_key(private_key_id)
            .unwrap()
            .thumbprint()
            .unwrap();

        let (_, invite) =
            Invite::make_for_private_key(TestSymmKey::Organization, &wrapped_private_key, &mut ctx)
                .unwrap();

        let invite_key = invite
            .unseal_invite_key_with_organization_key(TestSymmKey::Organization, &mut ctx)
            .unwrap();
        let recovered = invite
            .get_public_key_thumbprint(invite_key, &mut ctx)
            .unwrap();

        assert_eq!(recovered, expected);
    }

    #[test]
    fn test_invitee_recovers_organization_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);

        let (invite_secret, invite) =
            Invite::make_for_private_key(TestSymmKey::Organization, &wrapped_private_key, &mut ctx)
                .unwrap();

        // Using only the raw invite secret, an invitee can recover the invite key and then the
        // organization key.
        let invite_key = invite
            .unseal_invite_key_with_invite_secret(&invite_secret, &mut ctx)
            .unwrap();
        let recovered_org_key_id = invite
            .unseal_organization_key(invite_key, &mut ctx)
            .unwrap();

        ctx.assert_symmetric_keys_equal(recovered_org_key_id, TestSymmKey::Organization);
    }

    #[test]
    fn test_confirmation_toggle() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);

        let (invite_secret, mut invite) =
            Invite::make_for_private_key(TestSymmKey::Organization, &wrapped_private_key, &mut ctx)
                .unwrap();

        // New invites are created with confirmation enabled.
        assert!(invite.supports_confirmation());

        // Disabling confirmation removes the org-key envelope, so an invitee can no longer recover
        // the organization key.
        invite.disable_confirmation();
        assert!(!invite.supports_confirmation());
        let invite_key = invite
            .unseal_invite_key_with_invite_secret(&invite_secret, &mut ctx)
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
            .unseal_invite_key_with_invite_secret(&invite_secret, &mut ctx)
            .unwrap();
        let recovered_org_key_id = invite
            .unseal_organization_key(invite_key, &mut ctx)
            .unwrap();
        ctx.assert_symmetric_keys_equal(recovered_org_key_id, TestSymmKey::Organization);
    }

    #[test]
    fn test_invite_string_round_trip() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);

        let (invite_secret, invite) =
            Invite::make_for_private_key(TestSymmKey::Organization, &wrapped_private_key, &mut ctx)
                .unwrap();

        let encoded = String::from(&invite);
        let decoded: Invite = encoded.parse().unwrap();
        assert_eq!(String::from(&decoded), encoded);

        // The decoded invite still recovers the invite secret.
        let invite_key = decoded
            .unseal_invite_key_with_organization_key(TestSymmKey::Organization, &mut ctx)
            .unwrap();
        let recovered = decoded.get_invite_secret(invite_key, &mut ctx).unwrap();
        assert_eq!(invite_secret, recovered);

        // The custom serde impls delegate to the string round-trip.
        let json = serde_json::to_string(&invite).unwrap();
        let from_json: Invite = serde_json::from_str(&json).unwrap();
        assert_eq!(String::from(&from_json), encoded);
    }

    #[test]
    fn test_wrong_invite_secret_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);

        let (_, invite) =
            Invite::make_for_private_key(TestSymmKey::Organization, &wrapped_private_key, &mut ctx)
                .unwrap();

        // A different invite secret cannot unseal the invite key.
        let wrong_secret = InviteSecret(zeroize::Zeroizing::new([7u8; 32]));
        assert!(matches!(
            invite.unseal_invite_key_with_invite_secret(&wrong_secret, &mut ctx),
            Err(InviteKeyBundleError::KeyUnsealingFailed)
        ));
    }

    #[test]
    fn test_wrong_organization_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);

        let (_, invite) =
            Invite::make_for_private_key(TestSymmKey::Organization, &wrapped_private_key, &mut ctx)
                .unwrap();

        // A different organization key cannot unwrap the invite key.
        let wrong_org_key = ctx.generate_symmetric_key();
        assert!(matches!(
            invite.unseal_invite_key_with_organization_key(wrong_org_key, &mut ctx),
            Err(InviteKeyBundleError::KeyUnsealingFailed)
        ));
    }

    #[test]
    fn test_invitee_recovers_thumbprint() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);

        let private_key_id = ctx
            .unwrap_private_key(TestSymmKey::Organization, &wrapped_private_key)
            .unwrap();
        let expected = ctx
            .get_public_key(private_key_id)
            .unwrap()
            .thumbprint()
            .unwrap();

        let (invite_secret, invite) =
            Invite::make_for_private_key(TestSymmKey::Organization, &wrapped_private_key, &mut ctx)
                .unwrap();

        // The invitee reaches the invite key via the invite secret and reads the same bound
        // thumbprint the admin would.
        let invite_key = invite
            .unseal_invite_key_with_invite_secret(&invite_secret, &mut ctx)
            .unwrap();
        let recovered = invite
            .get_public_key_thumbprint(invite_key, &mut ctx)
            .unwrap();

        assert_eq!(recovered, expected);
    }

    #[test]
    fn test_malformed_invite_string_fails() {
        // Not JSON at all.
        assert!(matches!(
            "not valid json !!!".parse::<Invite>(),
            Err(InviteKeyBundleError::DecodingFailed)
        ));

        // Valid JSON, but missing the required invite fields.
        assert!(matches!(
            "{}".parse::<Invite>(),
            Err(InviteKeyBundleError::DecodingFailed)
        ));
    }

    #[test]
    fn test_invalid_wrapped_private_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);

        // The wrapped private key can only be unwrapped with the organization key it was wrapped
        // with; a different key makes `make_for_private_key` fail before building the invite.
        let wrong_org_key = ctx.generate_symmetric_key();
        assert!(matches!(
            Invite::make_for_private_key(wrong_org_key, &wrapped_private_key, &mut ctx),
            Err(InviteKeyBundleError::InvalidPrivateKey)
        ));
    }

    #[test]
    fn test_invite_secret_into_base64_url() {
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

    #[test]
    #[ignore = "Manual test to generate test vectors"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let org_key =
            SymmetricCryptoKey::try_from(B64::try_from(TEST_VECTOR_ORG_KEY).unwrap()).unwrap();
        let org_key_id = ctx.add_local_symmetric_key(org_key);

        // Make and wrap a fresh organization private key so it can be recorded as a fixed vector.
        let private_key_id = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapped_private_key = ctx.wrap_private_key(org_key_id, private_key_id).unwrap();

        let (invite_secret, invite) =
            Invite::make_for_private_key(org_key_id, &wrapped_private_key, &mut ctx).unwrap();

        println!(
            "const TEST_VECTOR_WRAPPED_PRIVATE_KEY: &str = \"{}\";",
            wrapped_private_key.to_string()
        );
        println!(
            "const TEST_VECTOR_INVITE: &str = r#\"{}\"#;",
            String::from(&invite)
        );
        println!(
            "const TEST_VECTOR_INVITE_SECRET: &str = \"{}\";",
            String::from(&invite_secret)
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
            .unseal_invite_key_with_organization_key(org_key_id, &mut ctx)
            .unwrap();
        let recovered = invite.get_invite_secret(invite_key, &mut ctx).unwrap();

        assert_eq!(String::from(&recovered), TEST_VECTOR_INVITE_SECRET);
    }

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_debug() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);

        let (invite_secret, invite) =
            Invite::make_for_private_key(TestSymmKey::Organization, &wrapped_private_key, &mut ctx)
                .unwrap();
        println!("{invite_secret:?}");
        println!("{invite:?}");
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
