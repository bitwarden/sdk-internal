//! End-to-end mint → parse → open tests. Per-field edge cases live in `token.rs`.

use bitwarden_crypto::{KeyStore, SymmetricCryptoKey, SymmetricKeyAlgorithm, key_slot_ids};
use bitwarden_sensitive_value::ExposeSensitive as _;
use uuid::{Uuid, uuid};

use crate::{AccessToken, AccessTokenKind, make_access_token_secrets};

key_slot_ids! {
    #[symmetric]
    enum TestSymmSlotId {
        Organization,
        #[local]
        Local(LocalId),
    }

    #[private]
    enum TestPrivateSlotId {
        #[local]
        Local(LocalId),
    }

    #[signing]
    enum TestSigningSlotId {
        #[local]
        Local(LocalId),
    }

    TestKeySlotIds => TestSymmSlotId, TestPrivateSlotId, TestSigningSlotId;
}

fn store_with_org_key() -> (KeyStore<TestKeySlotIds>, SymmetricCryptoKey) {
    let store: KeyStore<TestKeySlotIds> = KeyStore::default();
    let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);

    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(TestSymmSlotId::Organization, org_key.clone())
        .expect("set_symmetric_key");

    (store, org_key)
}

fn api_key_id() -> Uuid {
    uuid!("22222222-2222-2222-2222-222222222222")
}

/// Walks the whole mint → parse → open path for both kinds, so drift in either crate fails here.
#[test]
fn mint_then_parse_then_open_round_trip() {
    for kind in [
        AccessTokenKind::AccessConnector,
        AccessTokenKind::SecretsManager,
    ] {
        let (issuer_store, org_key) = store_with_org_key();

        let secrets = {
            let mut ctx = issuer_store.context_mut();
            make_access_token_secrets(&mut ctx, TestSymmSlotId::Organization, kind)
                .expect("mint secrets")
        };
        let encrypted_payload = secrets.encrypted_payload.to_string();
        let token_str = secrets.into_token(api_key_id(), "client-secret");

        // Everything below is what a holder does with nothing but the token string.
        let token = AccessToken::parse(&token_str, kind).expect("the token parses");
        assert_eq!(token.api_key_id(), api_key_id());
        assert_eq!(token.client_secret().expose(), "client-secret");

        let holder_store: KeyStore<TestKeySlotIds> = KeyStore::default();
        let mut ctx = holder_store.context_mut();
        token
            .open_payload(&mut ctx, &encrypted_payload, TestSymmSlotId::Organization)
            .expect("open_payload");

        #[allow(deprecated)]
        let recovered = ctx
            .dangerous_get_symmetric_key(TestSymmSlotId::Organization)
            .expect("the slot was just populated");
        assert_eq!(
            recovered.to_base64().to_string(),
            org_key.to_base64().to_string(),
            "the holder must recover the organization key verbatim"
        );
    }
}

#[test]
fn the_token_has_the_format_parse_expects() {
    let (issuer_store, _org_key) = store_with_org_key();
    let secrets = {
        let mut ctx = issuer_store.context_mut();
        make_access_token_secrets(
            &mut ctx,
            TestSymmSlotId::Organization,
            AccessTokenKind::AccessConnector,
        )
        .expect("mint secrets")
    };

    let token_str = secrets.into_token(api_key_id(), "secret");

    let (prefix, seed_b64) = token_str.split_once(':').expect("a `:` separates the seed");
    assert_eq!(
        prefix,
        format!("0.access-connector.{}.secret", api_key_id())
    );

    // The format requires exactly 16 bytes.
    let seed: bitwarden_encoding::B64 = seed_b64.parse().expect("the suffix is base64");
    assert_eq!(seed.as_bytes().len(), 16);
}
