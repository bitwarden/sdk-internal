//! This example demonstrates the lifecycle of an access token's key material: making it (issuer),
//! opening the payload with only the seed (token holder), and recovering the derived key with the
//! organization key (organization).

use bitwarden_access_token_crypto::{
    AccessTokenKey, AccessTokenKeyMaterial, AccessTokenSeed, KeyPurpose,
};
use bitwarden_crypto::{
    Decryptable, EncString, KeyStore, KeyStoreContext, PrimitiveEncryptable, SymmetricCryptoKey,
    SymmetricKeyAlgorithm::Aes256CbcHmac, key_slot_ids,
};
use bitwarden_encoding::B64;

fn main() {
    let key_store = KeyStore::<ExampleIds>::default();
    let mut ctx: KeyStoreContext<'_, ExampleIds> = key_store.context_mut();
    let org_id = uuid::Uuid::default();

    // 1. Set up an organization key. For the sdk, this is automatically done during
    // initialization by `init_org`. Persisting moves the key into the organization slot.
    let org_key = ExampleSymmetricKey::Organization(org_id);
    let local_org_key = ctx.make_symmetric_key(Aes256CbcHmac);
    ctx.persist_symmetric_key(local_org_key, org_key)
        .expect("switching key ids should work");

    // 2. Issuer: make the key material for a new access token. The purpose selects which key is
    // derived from the seed.
    let material = AccessTokenKeyMaterial::make(&mut ctx, org_key, KeyPurpose::AccessConnector)
        .expect("making key material should work");

    // `encrypted_payload` (the organization key encrypted under the derived key) and `key` (the
    // derived key encrypted under the organization key) are server-safe. Send both to the server.
    let encrypted_payload = material.encrypted_payload.clone();
    let key = material.key.clone();

    // The seed is the only secret the token holder needs.
    //
    // CRITICAL: the seed must never be sent to the server. Transport it to the token holder, e.g.
    // inside a token string.
    let seed_bytes = *material.into_seed().as_bytes();

    // 3. Token holder: holds ONLY the seed. Rebuild it from its bytes, derive the key for the same
    // purpose, and open the payload into an organization slot of a fresh key store.
    let holder_store = KeyStore::<ExampleIds>::default();
    let mut holder_ctx = holder_store.context_mut();
    let seed = AccessTokenSeed::try_from(seed_bytes.as_slice()).expect("seed has the right length");
    let holder_key = AccessTokenKey::derive(&seed, KeyPurpose::AccessConnector);
    let holder_org_key = ExampleSymmetricKey::Organization(uuid::Uuid::from_u128(1));
    holder_key
        .open_payload(
            &mut holder_ctx,
            &encrypted_payload.to_string(),
            holder_org_key,
        )
        .expect("the seed should open the payload");

    // The recovered organization key is equivalent to the original: what one encrypts, the other
    // decrypts.
    let secret: EncString = "organization secret"
        .encrypt(&mut holder_ctx, holder_org_key)
        .expect("encrypting with the recovered key should work");
    let decrypted: String = secret
        .decrypt(&mut ctx, org_key)
        .expect("the original organization key should decrypt it");
    assert_eq!(decrypted, "organization secret");

    // 4. Organization side: decrypting `key` with the organization key recovers the derived key,
    // without needing the token. It opens the payload the same way the token holder's does.
    let derived_key_b64: String = key
        .decrypt(&mut ctx, org_key)
        .expect("the organization key should decrypt the derived key");
    let derived_key = SymmetricCryptoKey::try_from(
        derived_key_b64
            .parse::<B64>()
            .expect("the derived key is valid base64"),
    )
    .expect("the derived key is a valid key");
    let local_derived_key = ExampleSymmetricKey::Organization(uuid::Uuid::from_u128(2));
    #[allow(deprecated)]
    ctx.set_symmetric_key(local_derived_key, derived_key)
        .expect("setting the key should work");
    let payload: String = encrypted_payload
        .decrypt(&mut ctx, local_derived_key)
        .expect("the recovered derived key should decrypt the payload");
    assert!(payload.contains("encryptionKey"));
}

key_slot_ids! {
    #[symmetric]
    pub enum ExampleSymmetricKey {
        Organization(uuid::Uuid),
        #[local]
        LocalKey(LocalId),
    }

    #[private]
    pub enum ExamplePrivateKey {
        #[local]
        LocalKey(LocalId),
    }

    #[signing]
    pub enum ExampleSigningKey {
        #[local]
        LocalKey(LocalId),
    }

    pub ExampleIds => ExampleSymmetricKey, ExamplePrivateKey, ExampleSigningKey;
}
