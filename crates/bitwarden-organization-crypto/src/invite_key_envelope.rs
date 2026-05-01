use bitwarden_crypto::{EncString, KeySlotIds, KeyStoreContext, SymmetricCryptoKey};
use bitwarden_encoding::B64Url;
use thiserror::Error;

/// Errors that can occur when creating an invite key envelope
#[derive(Debug, Error)]
pub enum InviteKeyEnvelopeError {
    /// The key wrapping failed while using the provided organization key
    #[error("Unable to wrap invite key with org key")]
    KeyWrappingFailed,
    /// The key_id was not found in the key context store
    #[error("Missing Key for Id: {0}")]
    MissingKeyId(String),
}

/// Struct for holding the invite key's raw data bytes
#[derive(Clone)]
pub struct InviteKeyData(SymmetricCryptoKey);

impl From<&InviteKeyData> for B64Url {
    fn from(key: &InviteKeyData) -> Self {
        B64Url::from(key.0.to_encoded().as_ref())
    }
}

/// A struct for holding the invitation key and the invitation key wrapped by
/// the organization key
pub struct InviteKeyBundle {
    raw_key_data: InviteKeyData,
    wrapped_invite_key: EncString,
}

impl InviteKeyBundle {
    /// Generates a brand new invitation key and wraps it with the provided
    /// organization key.
    pub fn make<Ids: KeySlotIds>(
        organization_key: Ids::Symmetric,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Self, InviteKeyEnvelopeError> {
        let key_id =
            ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::XChaCha20Poly1305);

        #[allow(deprecated)]
        let raw_key_data = InviteKeyData(
            ctx.dangerous_get_symmetric_key(key_id)
                .map_err(|_| InviteKeyEnvelopeError::MissingKeyId(format!("{key_id:?}")))?
                .clone(),
        );

        let wrapped_invite_key = ctx
            .wrap_symmetric_key(organization_key, key_id)
            .map_err(|_| InviteKeyEnvelopeError::KeyWrappingFailed)?;

        Ok(Self {
            raw_key_data,
            wrapped_invite_key,
        })
    }

    /// Get the raw invite key bytes in B64Url encoding
    /// CRITICAL: this data MUST NOT be sent to the server
    pub fn raw_invite_key(&self) -> B64Url {
        B64Url::from(&self.raw_key_data)
    }

    /// Get the invite key wrapped using the organization key
    pub fn organization_wrapped_invite_key(&self) -> &EncString {
        &self.wrapped_invite_key
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{BitwardenLegacyKeyBytes, KeyStore, SymmetricCryptoKey, key_slot_ids};
    use bitwarden_encoding::B64Url;

    use crate::invite_key_envelope::{InviteKeyBundle, InviteKeyData};

    #[test]
    fn test_basic_invitation_envelope_bundle() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();

        let key1 = InviteKeyBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();
        let key2 = InviteKeyBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();

        assert_ne!(key1.raw_key_data.0, key2.raw_key_data.0);
    }

    #[test]
    fn test_envelope_unseals_to_raw_bytes() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        let local_org_key_id = ctx.generate_symmetric_key();
        ctx.persist_symmetric_key(local_org_key_id, TestSymmKey::Organization)
            .unwrap();

        let key = InviteKeyBundle::make(TestSymmKey::Organization, &mut ctx).unwrap();

        let unsealed_key = ctx
            .unwrap_symmetric_key(TestSymmKey::Organization, &key.wrapped_invite_key)
            .unwrap();

        #[allow(deprecated)]
        let unsealed_key = ctx
            .dangerous_get_symmetric_key(unsealed_key)
            .unwrap()
            .clone();

        assert_eq!(key.raw_key_data.0, unsealed_key);
    }

    #[test]
    fn test_into_base64_url() {
        let data = b"+/=Hello, World!AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key =
            SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(data.to_vec())).unwrap();
        // let expected_raw_key_data = key.to_encoded().to_vec();

        let encoded = B64Url::from(&InviteKeyData(key));

        assert_eq!(encoded.as_bytes(), data);

        let encoded = encoded.to_string();
        assert_eq!(
            encoded,
            "Ky89SGVsbG8sIFdvcmxkIUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ"
        );
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));

        let decoded = B64Url::try_from(encoded.as_str()).unwrap();
        assert_eq!(decoded.as_bytes(), data);
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
