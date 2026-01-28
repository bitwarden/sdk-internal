//! This example demonstrates how to securely protect cryptographic keys with another symmetric key
//! using the [KeyProtectedKeyEnvelope].
//!
//! Unlike password-protected envelopes, this uses direct encryption without a.
//! This is suitable for scenarios where the wrapping key is already a strong symmetric key
//!
//! The envelope supports three types of keys:
//! - Symmetric keys (XChaCha20Poly1305, AES-256-CBC-HMAC)
//! - Private keys (RSA-2048)
//! - Signing keys (Ed25519)

use bitwarden_crypto::{
    CoseSerializable, KeyStore, KeyStoreContext, PublicKeyEncryptionAlgorithm, SignatureAlgorithm,
    SymmetricKeyAlgorithm, key_ids,
    safe::{KeyProtectedKeyEnvelope, KeyProtectedKeyEnvelopeNamespace},
};

fn main() {
    let key_store = KeyStore::<ExampleIds>::default();
    let mut ctx: KeyStoreContext<'_, ExampleIds> = key_store.context_mut();
    let mut disk = MockDisk::new();

    // Alice has a vault key that she wants to protect with a device-specific wrapping key.
    // The device key is a symmetric key

    let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
    let vault_key = ctx.generate_symmetric_key();

    // Seal the vault key with the wrapping key
    // This uses direct encryption with XChaCha20-Poly1305
    let envelope = KeyProtectedKeyEnvelope::seal_symmetric(vault_key, wrapping_key, KeyProtectedKeyEnvelopeNamespace::DeviceProtectedKey, &ctx)
        .expect("Sealing should work");

    // Persist the envelope to disk
    disk.save("vault_key_envelope", (&envelope).into());

    // Later, when needed: Load the envelope from disk and unseal it
    let deserialized: KeyProtectedKeyEnvelope = KeyProtectedKeyEnvelope::try_from(
        disk.load("vault_key_envelope")
            .expect("Loading from disk should work"),
    )
    .expect("Deserializing envelope should work");

    let unsealed_vault_key = deserialized
        .unseal_symmetric(wrapping_key, KeyProtectedKeyEnvelopeNamespace::DeviceProtectedKey, &mut ctx)
        .expect("Unsealing should work");

    assert_symmetric_keys_equal(&ctx, unsealed_vault_key, vault_key);

    // Bob wants to protect his RSA private key with a device key
    let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);

    // Seal the private key with the wrapping key (reusing from scenario 1)
    let envelope = KeyProtectedKeyEnvelope::seal_private(private_key, wrapping_key, KeyProtectedKeyEnvelopeNamespace::DeviceProtectedKey, &ctx)
        .expect("Sealing should work");

    disk.save("private_key_envelope", (&envelope).into());

    // Later: Load and unseal the private key
    let deserialized: KeyProtectedKeyEnvelope = KeyProtectedKeyEnvelope::try_from(
        disk.load("private_key_envelope")
            .expect("Loading from disk should work"),
    )
    .expect("Deserializing envelope should work");

    let unsealed_private_key = deserialized
        .unseal_private(wrapping_key, KeyProtectedKeyEnvelopeNamespace::DeviceProtectedKey, &mut ctx)
        .expect("Unsealing should work");

    assert_private_keys_equal(&ctx, unsealed_private_key, private_key);

    // Charlie wants to protect his Ed25519 signing key with a device key
    let signing_key = ctx.make_signing_key(SignatureAlgorithm::Ed25519);

    // Seal the signing key with the wrapping key (reusing from scenario 1)
    let envelope = KeyProtectedKeyEnvelope::seal_signing(signing_key, wrapping_key, KeyProtectedKeyEnvelopeNamespace::DeviceProtectedKey, &ctx)
        .expect("Sealing should work");

    disk.save("signing_key_envelope", (&envelope).into());

    // Later: Load and unseal the signing key
    let deserialized: KeyProtectedKeyEnvelope = KeyProtectedKeyEnvelope::try_from(
        disk.load("signing_key_envelope")
            .expect("Loading from disk should work"),
    )
    .expect("Deserializing envelope should work");

    let unsealed_signing_key = deserialized
        .unseal_signing(wrapping_key, KeyProtectedKeyEnvelopeNamespace::DeviceProtectedKey, &mut ctx)
        .expect("Unsealing should work");

    assert_signing_keys_equal(&ctx, unsealed_signing_key, signing_key);
}

pub(crate) struct MockDisk {
    map: std::collections::HashMap<String, Vec<u8>>,
}

impl MockDisk {
    pub(crate) fn new() -> Self {
        MockDisk {
            map: std::collections::HashMap::new(),
        }
    }

    pub(crate) fn save(&mut self, key: &str, value: Vec<u8>) {
        self.map.insert(key.to_string(), value);
    }

    pub(crate) fn load(&self, key: &str) -> Option<&Vec<u8>> {
        self.map.get(key)
    }
}

fn assert_symmetric_keys_equal(
    ctx: &KeyStoreContext<'_, ExampleIds>,
    left: ExampleSymmetricKey,
    right: ExampleSymmetricKey,
) {
    #[allow(deprecated)]
    let left_key = ctx
        .dangerous_get_symmetric_key(left)
        .expect("Left symmetric key should exist");
    #[allow(deprecated)]
    let right_key = ctx
        .dangerous_get_symmetric_key(right)
        .expect("Right symmetric key should exist");

    assert_eq!(left_key, right_key, "Symmetric keys differ");
}

fn assert_private_keys_equal(
    ctx: &KeyStoreContext<'_, ExampleIds>,
    left: ExamplePrivateKey,
    right: ExamplePrivateKey,
) {
    #[allow(deprecated)]
    let left_key = ctx
        .dangerous_get_private_key(left)
        .expect("Left private key should exist");
    #[allow(deprecated)]
    let right_key = ctx
        .dangerous_get_private_key(right)
        .expect("Right private key should exist");

    let left_der = left_key
        .to_der()
        .expect("Left private key should serialize to DER");
    let right_der = right_key
        .to_der()
        .expect("Right private key should serialize to DER");

    assert_eq!(left_der, right_der, "Private keys differ");
}

fn assert_signing_keys_equal(
    ctx: &KeyStoreContext<'_, ExampleIds>,
    left: ExampleSigningKey,
    right: ExampleSigningKey,
) {
    #[allow(deprecated)]
    let left_key = ctx
        .dangerous_get_signing_key(left)
        .expect("Left signing key should exist");
    #[allow(deprecated)]
    let right_key = ctx
        .dangerous_get_signing_key(right)
        .expect("Right signing key should exist");

    assert_eq!(
        left_key.to_verifying_key().to_cose(),
        right_key.to_verifying_key().to_cose(),
        "Signing keys differ"
    );
}

key_ids! {
    #[symmetric]
    pub enum ExampleSymmetricKey {
        Key(u8),
        #[local]
        Local(LocalId)
    }

    #[private]
    pub enum ExamplePrivateKey {
        Key(u8),
        #[local]
        Local(LocalId)
    }

    #[signing]
    pub enum ExampleSigningKey {
        Key(u8),
        #[local]
        Local(LocalId)
    }

    pub ExampleIds => ExampleSymmetricKey, ExamplePrivateKey, ExampleSigningKey;
}
