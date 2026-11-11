use std::str::FromStr;

use bitwarden_crypto::{
    CoseKeyBytes, CoseSerializable, CoseSign1Bytes, CryptoError, EncString, EncodingError, KeyId,
    PublicKey, SignedObject, SignedPublicKey, UnsignedSharedKey, VerifyingKey,
    compat::LegacyCompatSymmetricKeyEnvelope,
    safe::{DataEnvelope, PasswordProtectedKeyEnvelope, SymmetricKeyEnvelope},
};
use bitwarden_encoding::B64;

use crate::{
    ServerError,
    inspection::{CryptoObjectKeyIds, EncStringInfo, UnsignedSharedKeyInfo, hex},
};

/// Strict, keyless inspection: each method parses one SDK type and reports the key ids it names.
///
/// Nothing is decrypted or verified. Any invalid input returns [ServerError::InvalidData].
#[derive(uniffi::Object)]
pub struct CryptoParsingClient;

#[uniffi::export]
impl CryptoParsingClient {
    /// The id of the key `enc_string` was encrypted with, as 32 lowercase hex characters.
    ///
    /// [None] for legacy (non-COSE) EncStrings, which carry no key id.
    pub fn get_encrypted_by_key_id_encstring(
        &self,
        enc_string: String,
    ) -> Result<Option<String>, ServerError> {
        let enc_string = EncString::parse_strict(&enc_string)?;

        Ok(hex(enc_string.key_id()))
    }

    /// The id of the key sealed in `envelope`, as 32 lowercase hex characters.
    ///
    /// [None] if the envelope carries no key id.
    pub fn get_encrypted_by_key_id_symmetrickeyenvelope(
        &self,
        envelope: String,
    ) -> Result<Option<String>, ServerError> {
        let envelope = SymmetricKeyEnvelope::from_str(&envelope)?;

        Ok(hex(envelope.contained_key_id()?))
    }

    /// Inspects a symmetric EncString (type 0, 2 or 7).
    ///
    /// RSA-encrypted UnsignedSharedKeys (types 3 to 6) are not EncStrings and are rejected; use
    /// [CryptoParsingClient::inspect_unsigned_shared_key].
    pub fn inspect_enc_string(&self, enc_string: String) -> Result<EncStringInfo, ServerError> {
        let enc_string = EncString::parse_strict(&enc_string)?;

        EncStringInfo::try_from(&enc_string)
    }

    /// Inspects an RSA-encrypted UnsignedSharedKey (type 3 to 6). Names no key.
    pub fn inspect_unsigned_shared_key(
        &self,
        shared_key: String,
    ) -> Result<UnsignedSharedKeyInfo, ServerError> {
        let shared_key = UnsignedSharedKey::from_str(&shared_key)?;

        Ok(UnsignedSharedKeyInfo::from(&shared_key))
    }

    /// Inspects a SymmetricKeyEnvelope: the sealed key (if named) and the sealing key.
    pub fn inspect_symmetric_key_envelope(
        &self,
        envelope: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        let envelope = SymmetricKeyEnvelope::from_str(&envelope)?;

        Ok(CryptoObjectKeyIds {
            contained_key_id: hex(envelope.contained_key_id()?),
            encrypted_by_key_id: hex(Some(envelope.encrypted_by_key_id()?)),
            ..Default::default()
        })
    }

    /// Inspects a LegacyCompatSymmetricKeyEnvelope, in either form.
    ///
    /// The EncString form names no sealed key, and a sealing key only if it is COSE (type 7).
    pub fn inspect_legacy_compat_symmetric_key_envelope(
        &self,
        envelope: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        let envelope = LegacyCompatSymmetricKeyEnvelope::from_str(&envelope)?;

        // The SDK parses the EncString form laxly; reject what it could not read.
        if let LegacyCompatSymmetricKeyEnvelope::EncString(EncString::Unparseable { .. }) =
            &envelope
        {
            return Err(ServerError::InvalidData);
        }

        Ok(CryptoObjectKeyIds {
            contained_key_id: hex(envelope.contained_key_id()?),
            encrypted_by_key_id: hex(envelope.encrypted_by_key_id()?),
            ..Default::default()
        })
    }

    /// Inspects a PasswordProtectedKeyEnvelope: the sealed key, if named. Legacy (non-COSE) sealed
    /// keys have no id.
    pub fn inspect_password_protected_key_envelope(
        &self,
        envelope: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        let envelope = PasswordProtectedKeyEnvelope::from_str(&envelope)?;

        Ok(CryptoObjectKeyIds {
            contained_key_id: hex(envelope.contained_key_id()?),
            ..Default::default()
        })
    }

    /// Inspects a DataEnvelope: the content-encryption key it is sealed with.
    pub fn inspect_data_envelope(
        &self,
        envelope: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        let envelope = DataEnvelope::from_str(&envelope).map_err(|_| ServerError::InvalidData)?;

        Ok(CryptoObjectKeyIds {
            encrypted_by_key_id: hex(Some(envelope.encrypted_by_key_id()?)),
            ..Default::default()
        })
    }

    /// Inspects a base64 COSE Sign1 SignedObject: the signing key.
    pub fn inspect_signed_object(
        &self,
        signed_object: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        Ok(signed_by_ids(signed_by(&signed_object)?))
    }

    /// Inspects a SignedPublicKey: the signing key.
    pub fn inspect_signed_public_key(
        &self,
        signed_public_key: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        let signed_public_key =
            SignedPublicKey::from_str(&signed_public_key).map_err(|_| ServerError::InvalidData)?;

        // SignedPublicKey hides its SignedObject; re-read the same COSE bytes as one.
        let bytes = CoseSign1Bytes::from(signed_public_key);
        let signed_by = SignedObject::from_cose(&bytes)?.signed_by_id()?;

        Ok(signed_by_ids(signed_by))
    }

    /// Inspects a base64 COSE VerifyingKey: its own id, as `contained_key_id`.
    pub fn inspect_verifying_key(
        &self,
        verifying_key: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        let bytes = B64::try_from(verifying_key.as_str()).map_err(|_| ServerError::InvalidData)?;
        let verifying_key = VerifyingKey::from_cose(&CoseKeyBytes::from(&bytes))?;

        Ok(CryptoObjectKeyIds {
            contained_key_id: hex(Some(verifying_key.key_id())),
            ..Default::default()
        })
    }

    /// Validates a base64 DER SPKI RSA PublicKey. The SDK defines no key id for it, so all ids are
    /// [None].
    pub fn inspect_public_key(
        &self,
        public_key: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        PublicKey::from_str(&public_key).map_err(|_| ServerError::InvalidData)?;

        Ok(CryptoObjectKeyIds::default())
    }

    /// Inspects a SignedSecurityState: the signing key.
    ///
    /// Its version is not returned: the SDK only reads it after verifying the signature.
    pub fn inspect_signed_security_state(
        &self,
        signed_security_state: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        // SignedSecurityState lives in bitwarden-core, too heavy for this crate. Its wire format is
        // a base64 SignedObject, which is what its own parser reads.
        Ok(signed_by_ids(signed_by(&signed_security_state)?))
    }
}

/// Parses a base64 COSE Sign1 SignedObject and returns its signing key id.
fn signed_by(signed_object: &str) -> Result<KeyId, CryptoError> {
    let bytes = B64::try_from(signed_object).map_err(|_| EncodingError::InvalidBase64Encoding)?;
    let signed_object = SignedObject::from_cose(&CoseSign1Bytes::from(&bytes))?;

    signed_object.signed_by_id()
}

/// Key ids of a signed object, which names only its signer.
fn signed_by_ids(signed_by: KeyId) -> CryptoObjectKeyIds {
    CryptoObjectKeyIds {
        signed_by_key_id: hex(Some(signed_by)),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{
        KeyStore, PrimitiveEncryptable, PublicKeyEncryptionAlgorithm, SignatureAlgorithm,
        SigningNamespace, SymmetricKeyAlgorithm, generate_versioned_sealable, key_slot_ids,
        safe::{
            DataEnvelopeNamespace, PasswordProtectedKeyEnvelopeNamespace, SealableData,
            SealableVersionedData, SymmetricKeyEnvelope, SymmetricKeyEnvelopeNamespace,
        },
    };
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::{EncStringAlgorithm, ServerClient, UnsignedSharedKeyAlgorithm};

    /// Reaches the sub-client the way bindings do, through [ServerClient].
    fn client() -> CryptoParsingClient {
        ServerClient::new().crypto_parsing()
    }

    key_slot_ids! {
        #[symmetric]
        pub enum TestSymmKey {
            #[local]
            Local(LocalId),
        }

        #[private]
        pub enum TestPrivateKey {
            #[local]
            Local(LocalId),
        }

        #[signing]
        pub enum TestSigningKey {
            #[local]
            Local(LocalId),
        }

        pub TestIds => TestSymmKey, TestPrivateKey, TestSigningKey;
    }

    // Fixed inputs, mirrored in the dotnet-extensions tests. `COSE_ENCSTRING` is encrypted with,
    // and `ENVELOPE` seals, the XAES-256-GCM key `FIXTURE_KEY_ID`.
    const FIXTURE_KEY_ID: &str = "786b476843503fe1f6deb3951ef8f037";
    const COSE_ENCSTRING: &str = "7.g1g/owE6AAEReQN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLnV0ZjgtcGFkZGVkBFB4a0doQ1A/4fbes5Ue+PA3oQVYGDyfZwmpm8qoMQ6T/GkNaSNiH0xURegyi1gwqCiYSKv1pO6JGK65CMOYx4dAUaqpKz5JlvFE/XdTX6VcOggf2PX0H9iCB/rDjvng";
    const LEGACY_ENCSTRING: &str = "2.lydV844NLeMlZyw+lBvavQ==|g/ybWBsaTkyTDJYL1kcrZQ==|2ZeoX1YiRQoaowBuGS7feAH9PZvz3VDy6QuPtMNu7R4=";
    const ENVELOPE: &str = "g1g+pgE6AAEReQMYZQRQ8UUgSvckp9zxEdxy+99QTDoAARVcUHhrR2hDUD/h9t6zlR748Dc6AAE4gQM6AAE4gAKhBVgYHYM4amZXcPx+ioIiaBQXy/itml3h/5kpWFR2SQ9uMP9TBs/iL2+tuzwOcGtphqCkEpSBBlifIzT9oow7+hYJ9N4hKxXYLEn0ldNDdfi7ryjXgAscY0OTDPOEIwUaqJZGKESUEDDhohHVoaGgZrY=";

    #[test]
    fn fixtures_return_expected_key_ids() {
        let client = client();
        let expected = Some(FIXTURE_KEY_ID.to_string());

        let cose = client.get_encrypted_by_key_id_encstring(COSE_ENCSTRING.into());
        let legacy = client.get_encrypted_by_key_id_encstring(LEGACY_ENCSTRING.into());
        let envelope = client.get_encrypted_by_key_id_symmetrickeyenvelope(ENVELOPE.into());

        assert_eq!(cose.expect("valid"), expected);
        assert_eq!(legacy.expect("valid"), None);
        assert_eq!(envelope.expect("valid"), expected);
    }

    #[test]
    fn encstring_key_id_matches_encrypting_key() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let expected = ctx.get_symmetric_key_id(key).map(|id| id.to_string());

        let enc_string = "secret".encrypt(&mut ctx, key).expect("encrypts");
        let actual = client()
            .get_encrypted_by_key_id_encstring(enc_string.to_string())
            .expect("valid EncString");

        assert!(expected.is_some());
        assert_eq!(actual, expected);
    }

    #[test]
    fn encstring_legacy_has_no_key_id() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let enc_string = "secret".encrypt(&mut ctx, key).expect("encrypts");
        let actual = client()
            .get_encrypted_by_key_id_encstring(enc_string.to_string())
            .expect("valid EncString");

        assert_eq!(actual, None);
    }

    #[test]
    fn encstring_invalid_is_error() {
        let result = client().get_encrypted_by_key_id_encstring("garbage".into());

        assert!(matches!(result, Err(ServerError::InvalidData)));
    }

    #[test]
    fn envelope_key_id_matches_sealed_key() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let sealed = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let wrapping = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let expected = ctx.get_symmetric_key_id(sealed).map(|id| id.to_string());

        let envelope = SymmetricKeyEnvelope::seal(
            sealed,
            wrapping,
            SymmetricKeyEnvelopeNamespace::OrganizationInvite,
            &ctx,
        )
        .expect("seals");
        let actual = client()
            .get_encrypted_by_key_id_symmetrickeyenvelope(String::from(envelope))
            .expect("valid envelope");

        assert!(expected.is_some());
        assert_eq!(actual, expected);
    }

    #[test]
    fn envelope_invalid_is_error() {
        let result = client().get_encrypted_by_key_id_symmetrickeyenvelope("garbage".into());

        assert!(matches!(result, Err(ServerError::InvalidData)));
    }

    // Test payloads. `SecurityStateStub` mirrors bitwarden-core's `SecurityState`.
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct TestItemV1 {
        field: u32,
    }
    impl SealableData for TestItemV1 {}

    generate_versioned_sealable!(TestItem, DataEnvelopeNamespace::VaultItem, [TestItemV1 => "1"]);

    #[derive(Serialize)]
    struct SecurityStateStub {
        version: u64,
    }

    const GARBAGE: &str = "garbage";

    /// Base64 of a COSE Sign1 object, the wire format of SignedObject and SignedSecurityState.
    fn to_b64(object: &SignedObject) -> String {
        B64::from(object.to_cose().as_ref()).to_string()
    }

    fn id(key_id: Option<KeyId>) -> Option<String> {
        assert!(key_id.is_some());
        key_id.map(|id| id.to_string())
    }

    #[test]
    fn inspect_enc_string_cose() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();

        let key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let enc_string = "secret".encrypt(&mut ctx, key).expect("encrypts");

        let info = client()
            .inspect_enc_string(enc_string.to_string())
            .expect("valid EncString");

        assert_eq!(
            info,
            EncStringInfo {
                algorithm: EncStringAlgorithm::XAes256Gcm,
                encrypted_by_key_id: id(ctx.get_symmetric_key_id(key)),
            }
        );
    }

    // Type 0 has no MAC, so it cannot be produced by the SDK; parse a well-formed literal.
    #[test]
    fn inspect_enc_string_aes256_cbc() {
        let info = client()
            .inspect_enc_string("0.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==".into())
            .expect("valid EncString");

        assert_eq!(
            info,
            EncStringInfo {
                algorithm: EncStringAlgorithm::Aes256Cbc,
                encrypted_by_key_id: None,
            }
        );
    }

    #[test]
    fn inspect_enc_string_legacy() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let enc_string = "secret".encrypt(&mut ctx, key).expect("encrypts");

        let info = client()
            .inspect_enc_string(enc_string.to_string())
            .expect("valid EncString");

        assert_eq!(info.algorithm, EncStringAlgorithm::Aes256CbcHmac);
        assert_eq!(info.encrypted_by_key_id, None);
    }

    // UnsignedSharedKeys share the `<type>.<payload>` format but are not EncStrings.
    #[test]
    fn inspect_enc_string_rejects_unsigned_shared_key() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let shared = make_shared_key(&mut ctx);

        let result = client().inspect_enc_string(shared);

        assert!(matches!(result, Err(ServerError::InvalidData)));
    }

    #[test]
    fn inspect_enc_string_invalid() {
        let client = client();

        for input in [GARBAGE, "2.AAAA|AAAA", "9.AAAA"] {
            let result = client.inspect_enc_string(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    /// Encapsulates a fresh symmetric key to a fresh RSA public key.
    fn make_shared_key(ctx: &mut bitwarden_crypto::KeyStoreContext<TestIds>) -> String {
        let private = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let public = ctx.get_public_key(private).expect("public key");
        let key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        UnsignedSharedKey::encapsulate(key, &public, ctx)
            .expect("encapsulates")
            .to_string()
    }

    #[test]
    fn inspect_unsigned_shared_key_round_trip() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let shared = make_shared_key(&mut ctx);

        let info = client()
            .inspect_unsigned_shared_key(shared)
            .expect("valid UnsignedSharedKey");

        assert_eq!(info.algorithm, UnsignedSharedKeyAlgorithm::Rsa2048OaepSha1);
    }

    #[test]
    fn inspect_unsigned_shared_key_rejects_symmetric() {
        let client = client();

        for input in [GARBAGE, COSE_ENCSTRING, LEGACY_ENCSTRING] {
            let result = client.inspect_unsigned_shared_key(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_symmetric_key_envelope_round_trip() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let sealed = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let wrapping = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let envelope = SymmetricKeyEnvelope::seal(
            sealed,
            wrapping,
            SymmetricKeyEnvelopeNamespace::OrganizationInvite,
            &ctx,
        )
        .expect("seals");

        let ids = client()
            .inspect_symmetric_key_envelope(String::from(envelope))
            .expect("valid envelope");

        assert_eq!(
            ids,
            CryptoObjectKeyIds {
                contained_key_id: id(ctx.get_symmetric_key_id(sealed)),
                encrypted_by_key_id: id(ctx.get_symmetric_key_id(wrapping)),
                signed_by_key_id: None,
            }
        );
    }

    #[test]
    fn inspect_symmetric_key_envelope_fixture() {
        let ids = client()
            .inspect_symmetric_key_envelope(ENVELOPE.into())
            .expect("valid envelope");

        assert_eq!(ids.contained_key_id, Some(FIXTURE_KEY_ID.to_string()));
        assert!(ids.encrypted_by_key_id.is_some());
    }

    #[test]
    fn inspect_symmetric_key_envelope_invalid() {
        let client = client();

        for input in [GARBAGE, COSE_ENCSTRING] {
            let result = client.inspect_symmetric_key_envelope(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_legacy_compat_envelope_form() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let sealed = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let wrapping = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let envelope = LegacyCompatSymmetricKeyEnvelope::seal(
            sealed,
            wrapping,
            SymmetricKeyEnvelopeNamespace::OrganizationInvite,
            &ctx,
        )
        .expect("seals");

        let ids = client()
            .inspect_legacy_compat_symmetric_key_envelope(envelope.to_string())
            .expect("valid envelope");

        assert_eq!(ids.contained_key_id, id(ctx.get_symmetric_key_id(sealed)));
        assert_eq!(
            ids.encrypted_by_key_id,
            id(ctx.get_symmetric_key_id(wrapping))
        );
    }

    #[test]
    fn inspect_legacy_compat_enc_string_form() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let sealed = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let wrapping = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let envelope = LegacyCompatSymmetricKeyEnvelope::seal_legacy(
            sealed,
            wrapping,
            SymmetricKeyEnvelopeNamespace::OrganizationInvite,
            &ctx,
        )
        .expect("seals");

        let ids = client()
            .inspect_legacy_compat_symmetric_key_envelope(envelope.to_string())
            .expect("valid envelope");

        assert_eq!(ids.contained_key_id, None);
        assert_eq!(
            ids.encrypted_by_key_id,
            id(ctx.get_symmetric_key_id(wrapping))
        );
    }

    #[test]
    fn inspect_legacy_compat_invalid() {
        let client = client();

        for input in [GARBAGE, "2.AAAA|AAAA"] {
            let result = client.inspect_legacy_compat_symmetric_key_envelope(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_password_protected_envelope_round_trip() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let sealed = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let envelope = PasswordProtectedKeyEnvelope::seal(
            sealed,
            "password",
            PasswordProtectedKeyEnvelopeNamespace::PinUnlock,
            &ctx,
        )
        .expect("seals");

        let ids = client()
            .inspect_password_protected_key_envelope(String::from(envelope))
            .expect("valid envelope");

        assert_eq!(
            ids,
            CryptoObjectKeyIds {
                contained_key_id: id(ctx.get_symmetric_key_id(sealed)),
                ..Default::default()
            }
        );
    }

    #[test]
    fn inspect_password_protected_envelope_invalid() {
        let client = client();

        for input in [GARBAGE, ENVELOPE] {
            let result = client.inspect_password_protected_key_envelope(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_data_envelope_round_trip() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let item: TestItem = TestItemV1 { field: 1 }.into();
        let (envelope, cek) = DataEnvelope::seal(item, &mut ctx).expect("seals");

        let ids = client()
            .inspect_data_envelope(envelope.to_string())
            .expect("valid envelope");

        assert_eq!(
            ids,
            CryptoObjectKeyIds {
                encrypted_by_key_id: id(ctx.get_symmetric_key_id(cek)),
                ..Default::default()
            }
        );
    }

    #[test]
    fn inspect_data_envelope_invalid() {
        let client = client();

        // Not base64; base64 but not COSE.
        for input in [GARBAGE, "AAAA"] {
            let result = client.inspect_data_envelope(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_signed_object_round_trip() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let signing = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let expected = ctx.get_verifying_key(signing).expect("exists").key_id();
        let signed = ctx
            .sign(
                signing,
                &SecurityStateStub { version: 2 },
                &SigningNamespace::SecurityState,
            )
            .expect("signs");

        let ids = client()
            .inspect_signed_object(to_b64(&signed))
            .expect("valid SignedObject");

        assert_eq!(
            ids,
            CryptoObjectKeyIds {
                signed_by_key_id: id(Some(expected)),
                ..Default::default()
            }
        );
    }

    #[test]
    fn inspect_signed_object_invalid() {
        let client = client();

        for input in [GARBAGE, "AAAA"] {
            let result = client.inspect_signed_object(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_signed_public_key_round_trip() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let signing = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let private = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let expected = ctx.get_verifying_key(signing).expect("exists").key_id();
        let signed = ctx.make_signed_public_key(private, signing).expect("signs");

        let ids = client()
            .inspect_signed_public_key(String::from(signed))
            .expect("valid SignedPublicKey");

        assert_eq!(ids.signed_by_key_id, id(Some(expected)));
        assert_eq!(ids.contained_key_id, None);
    }

    #[test]
    fn inspect_signed_public_key_invalid() {
        let client = client();

        for input in [GARBAGE, "AAAA"] {
            let result = client.inspect_signed_public_key(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_verifying_key_round_trip() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();

        for algorithm in [SignatureAlgorithm::Ed25519, SignatureAlgorithm::MlDsa44] {
            let signing = ctx.make_signing_key(algorithm);
            let verifying = ctx.get_verifying_key(signing).expect("exists");
            let encoded = B64::from(verifying.to_cose().as_ref()).to_string();

            let ids = client()
                .inspect_verifying_key(encoded)
                .expect("valid VerifyingKey");

            assert_eq!(
                ids,
                CryptoObjectKeyIds {
                    contained_key_id: id(Some(verifying.key_id())),
                    ..Default::default()
                }
            );
        }
    }

    #[test]
    fn inspect_verifying_key_invalid() {
        let client = client();

        for input in [GARBAGE, "AAAA"] {
            let result = client.inspect_verifying_key(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_public_key_round_trip() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let private = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let public = ctx.get_public_key(private).expect("exists");

        let ids = client()
            .inspect_public_key(public.to_string())
            .expect("valid PublicKey");

        assert_eq!(ids, CryptoObjectKeyIds::default());
    }

    #[test]
    fn inspect_public_key_invalid() {
        let client = client();

        for input in [GARBAGE, "AAAA"] {
            let result = client.inspect_public_key(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_signed_security_state_round_trip() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let signing = ctx.make_signing_key(SignatureAlgorithm::Ed25519);
        let expected = ctx.get_verifying_key(signing).expect("exists").key_id();
        let signed = ctx
            .sign(
                signing,
                &SecurityStateStub { version: 2 },
                &SigningNamespace::SecurityState,
            )
            .expect("signs");

        let ids = client()
            .inspect_signed_security_state(to_b64(&signed))
            .expect("valid SignedSecurityState");

        assert_eq!(ids.signed_by_key_id, id(Some(expected)));
    }

    #[test]
    fn inspect_signed_security_state_invalid() {
        let client = client();

        for input in [GARBAGE, "AAAA"] {
            let result = client.inspect_signed_security_state(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }
}
