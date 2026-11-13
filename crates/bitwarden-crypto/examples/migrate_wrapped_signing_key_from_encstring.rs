//! This example demonstrates how to migrate a stored, wrapped signing key from a legacy
//! [`EncString`](bitwarden_crypto::EncString) to a
//! [`SigningKeyEnvelope`](bitwarden_crypto::safe::SigningKeyEnvelope) using the
//! [`LegacyCompatSigningKeyEnvelope`].
//!
//! Signing keys should no longer be stored as EncStrings, but use this compatibility helper for
//! migration, or Signing Key Envelope directly for new use-cases.
//!
//! The migration spans several releases. Each module below is the persisted struct as it looks in
//! one release, together with how that release writes and reads it:
//!
//! ```text
//!   release    field type                       writes                   readable by
//!   ─────────  ───────────────────────────────  ───────────────────────  ───────────
//!   < N        EncString                        wrap_signing_key         all
//!   N .. N+2   LegacyCompatSigningKeyEnvelope   seal_legacy (EncString)  all
//!   >= N+3     LegacyCompatSigningKeyEnvelope   seal (envelope)          >= N only
//! ```
//!
//! In order to migrate, add support via `seal_legacy`, then three full releases later, switch to
//! `seal`. This is a breaking change: releases before N cannot read the envelope.

use bitwarden_crypto::{
    CryptoError, KeyStore, KeyStoreContext, SignatureAlgorithm, SymmetricKeyAlgorithm,
    compat::LegacyCompatSigningKeyEnvelope,
    key_slot_ids,
    safe::{SigningKeyEnvelopeError, SigningKeyEnvelopeNamespace},
};
use serde::{Deserialize, Serialize};

// The namespace must be replaced with an appropriate namespace for the use-case
const NAMESPACE: SigningKeyEnvelopeNamespace = SigningKeyEnvelopeNamespace::UserSigningKey;

type Ctx<'a> = KeyStoreContext<'a, ExampleIds>;

/// Releases before N: the signing key is stored as an EncString.
mod before_migration {
    use bitwarden_crypto::EncString;

    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct StoredSigningKey {
        pub(crate) wrapped_key: EncString,
    }

    pub(crate) fn seal(
        signing_key: ExampleSigningKey,
        wrapping_key: ExampleSymmetricKey,
        ctx: &Ctx,
    ) -> StoredSigningKey {
        StoredSigningKey {
            wrapped_key: ctx
                .wrap_signing_key(wrapping_key, signing_key)
                .expect("Wrapping should work"),
        }
    }

    pub(crate) fn unseal(
        stored: &StoredSigningKey,
        wrapping_key: ExampleSymmetricKey,
        ctx: &mut Ctx,
    ) -> Result<ExampleSigningKey, CryptoError> {
        ctx.unwrap_signing_key(wrapping_key, &stored.wrapped_key)
    }
}

/// Releases N to N+2: the field type changes, so both formats are read. Writing stays on the
/// legacy format, so releases before N can still read the data.
mod release_n {
    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct StoredSigningKey {
        pub(crate) wrapped_key: LegacyCompatSigningKeyEnvelope,
    }

    pub(crate) fn seal(
        signing_key: ExampleSigningKey,
        wrapping_key: ExampleSymmetricKey,
        ctx: &Ctx,
    ) -> StoredSigningKey {
        StoredSigningKey {
            wrapped_key: LegacyCompatSigningKeyEnvelope::seal_legacy(
                signing_key,
                wrapping_key,
                NAMESPACE,
                ctx,
            )
            .expect("Sealing should work"),
        }
    }

    pub(crate) fn unseal(
        stored: &StoredSigningKey,
        wrapping_key: ExampleSymmetricKey,
        ctx: &mut Ctx,
    ) -> Result<ExampleSigningKey, SigningKeyEnvelopeError> {
        stored.wrapped_key.unseal(wrapping_key, NAMESPACE, ctx)
    }
}

/// Release N+3 onwards: every supported release reads the envelope, so writing switches from
/// `seal_legacy` to `seal`. The struct is unchanged; existing EncStrings migrate on re-seal.
mod release_n_plus_3 {
    pub(crate) use release_n::{StoredSigningKey, unseal};

    use super::*;

    pub(crate) fn seal(
        signing_key: ExampleSigningKey,
        wrapping_key: ExampleSymmetricKey,
        ctx: &Ctx,
    ) -> StoredSigningKey {
        StoredSigningKey {
            wrapped_key: LegacyCompatSigningKeyEnvelope::seal(
                signing_key,
                wrapping_key,
                NAMESPACE,
                ctx,
            )
            .expect("Sealing should work"),
        }
    }
}

fn main() {
    let key_store = KeyStore::<ExampleIds>::default();
    let mut ctx: Ctx = key_store.context_mut();

    // A signing key wrapped by a V1 (AES-256-CBC-HMAC) user key.
    let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let signing_key = ctx.make_signing_key(SignatureAlgorithm::Ed25519);

    // Before migration: data at rest is an EncString, e.g. {"wrappedKey":"2.iv|data|mac"}.
    let disk = to_json(&before_migration::seal(signing_key, wrapping_key, &ctx));

    // Release N reads existing data.
    let stored: release_n::StoredSigningKey = from_json(&disk);
    let _signing_key =
        release_n::unseal(&stored, wrapping_key, &mut ctx).expect("Release N reads EncStrings");

    // Release N writes EncStrings, so releases before N still read its data.
    let disk = to_json(&release_n::seal(signing_key, wrapping_key, &ctx));
    let stored: before_migration::StoredSigningKey = from_json(&disk);
    let _signing_key = before_migration::unseal(&stored, wrapping_key, &mut ctx)
        .expect("Releases before N read data written by release N");

    // Release N+3 reads existing EncStrings and re-seals them as envelopes,
    // e.g. {"wrappedKey":"g1g+pgE6..."}.
    let stored: release_n_plus_3::StoredSigningKey = from_json(&disk);
    let unsealed = release_n_plus_3::unseal(&stored, wrapping_key, &mut ctx)
        .expect("Release N+3 reads EncStrings");
    let disk = to_json(&release_n_plus_3::seal(unsealed, wrapping_key, &ctx));
    assert!(matches!(
        from_json::<release_n_plus_3::StoredSigningKey>(&disk).wrapped_key,
        LegacyCompatSigningKeyEnvelope::SigningKeyEnvelope(_)
    ));

    // Releases N to N+2 read the envelope.
    let stored: release_n::StoredSigningKey = from_json(&disk);
    let _signing_key =
        release_n::unseal(&stored, wrapping_key, &mut ctx).expect("Release N reads envelopes");

    // Releases before N cannot. This is the breaking change.
    let stored: before_migration::StoredSigningKey = from_json(&disk);
    assert!(before_migration::unseal(&stored, wrapping_key, &mut ctx).is_err());
}

fn to_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("Serializing should work")
}

fn from_json<T: for<'de> Deserialize<'de>>(json: &str) -> T {
    serde_json::from_str(json).expect("Deserializing should work")
}

key_slot_ids! {
    #[symmetric]
    pub enum ExampleSymmetricKey {
        #[local]
        UserKey(LocalId),
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
