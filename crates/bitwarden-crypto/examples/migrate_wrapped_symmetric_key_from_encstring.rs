//! This example demonstrates how to migrate a stored, wrapped symmetric key from a legacy
//! [`EncString`](bitwarden_crypto::EncString) to a
//! [`SymmetricKeyEnvelope`](bitwarden_crypto::safe::SymmetricKeyEnvelope) using the
//! [`LegacyCompatSymmetricKeyEnvelope`].
//!
//! Symmetric keys should no longer be stored as EncStrings, but use this compatibility helper for
//! migration, or Symmetric Key Envelope directly for new use-cases.
//!
//! The migration spans several releases. Each module below is the persisted struct as it looks in
//! one release, together with how that release writes and reads it:
//!
//! ```text
//!   release    field type                         writes                   readable by
//!   ─────────  ─────────────────────────────────  ───────────────────────  ───────────
//!   < N        EncString                          wrap_symmetric_key       all
//!   N .. N+2   LegacyCompatSymmetricKeyEnvelope   seal_legacy (EncString)  all
//!   >= N+3     LegacyCompatSymmetricKeyEnvelope   seal (envelope)          >= N only
//! ```
//!
//! In order to migrate, add support via `seal_legacy`, then three full releases later, switch to
//! `seal`. This is a breaking change: releases before N cannot read the envelope.

use bitwarden_crypto::{
    CryptoError, KeyStore, KeyStoreContext, SymmetricKeyAlgorithm,
    compat::LegacyCompatSymmetricKeyEnvelope,
    key_slot_ids,
    safe::{SymmetricKeyEnvelopeError, SymmetricKeyEnvelopeNamespace},
};
use serde::{Deserialize, Serialize};

// The namespace must be replaced with an appropriate namespace for the use-case
const NAMESPACE: SymmetricKeyEnvelopeNamespace = SymmetricKeyEnvelopeNamespace::SessionKey;

type Ctx<'a> = KeyStoreContext<'a, ExampleIds>;

/// Releases before N: the key is stored as an EncString.
mod before_migration {
    use bitwarden_crypto::EncString;

    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct StoredVaultKey {
        pub(crate) wrapped_key: EncString,
    }

    pub(crate) fn seal(
        vault_key: ExampleSymmetricKey,
        wrapping_key: ExampleSymmetricKey,
        ctx: &Ctx,
    ) -> StoredVaultKey {
        StoredVaultKey {
            wrapped_key: ctx
                .wrap_symmetric_key(wrapping_key, vault_key)
                .expect("Wrapping should work"),
        }
    }

    pub(crate) fn unseal(
        stored: &StoredVaultKey,
        wrapping_key: ExampleSymmetricKey,
        ctx: &mut Ctx,
    ) -> Result<ExampleSymmetricKey, CryptoError> {
        ctx.unwrap_symmetric_key(wrapping_key, &stored.wrapped_key)
    }
}

/// Releases N to N+2: the field type changes, so both formats are read. Writing stays on the
/// legacy format, so releases before N can still read the data.
mod release_n {
    use super::*;

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct StoredVaultKey {
        pub(crate) wrapped_key: LegacyCompatSymmetricKeyEnvelope,
    }

    pub(crate) fn seal(
        vault_key: ExampleSymmetricKey,
        wrapping_key: ExampleSymmetricKey,
        ctx: &Ctx,
    ) -> StoredVaultKey {
        StoredVaultKey {
            wrapped_key: LegacyCompatSymmetricKeyEnvelope::seal_legacy(
                vault_key,
                wrapping_key,
                NAMESPACE,
                ctx,
            )
            .expect("Sealing should work"),
        }
    }

    pub(crate) fn unseal(
        stored: &StoredVaultKey,
        wrapping_key: ExampleSymmetricKey,
        ctx: &mut Ctx,
    ) -> Result<ExampleSymmetricKey, SymmetricKeyEnvelopeError> {
        stored.wrapped_key.unseal(wrapping_key, NAMESPACE, ctx)
    }
}

/// Release N+3 onwards: every supported release reads the envelope, so writing switches from
/// `seal_legacy` to `seal`. The struct is unchanged; existing EncStrings migrate on re-seal.
mod release_n_plus_3 {
    pub(crate) use release_n::{StoredVaultKey, unseal};

    use super::*;

    pub(crate) fn seal(
        vault_key: ExampleSymmetricKey,
        wrapping_key: ExampleSymmetricKey,
        ctx: &Ctx,
    ) -> StoredVaultKey {
        StoredVaultKey {
            wrapped_key: LegacyCompatSymmetricKeyEnvelope::seal(
                vault_key,
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

    // A vault key wrapped by a V1 (AES-256-CBC-HMAC) key.
    let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
    let vault_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

    // Before migration: data at rest is an EncString, e.g. {"wrappedKey":"2.iv|data|mac"}.
    let disk = to_json(&before_migration::seal(vault_key, wrapping_key, &ctx));

    // Release N reads existing data.
    let stored: release_n::StoredVaultKey = from_json(&disk);
    let _vault_key =
        release_n::unseal(&stored, wrapping_key, &mut ctx).expect("Release N reads EncStrings");

    // Release N writes EncStrings, so releases before N still read its data.
    let disk = to_json(&release_n::seal(vault_key, wrapping_key, &ctx));
    let stored: before_migration::StoredVaultKey = from_json(&disk);
    let _vault_key = before_migration::unseal(&stored, wrapping_key, &mut ctx)
        .expect("Releases before N read data written by release N");

    // Release N+3 reads existing EncStrings and re-seals them as envelopes,
    // e.g. {"wrappedKey":"g1hgpgE6..."}.
    let stored: release_n_plus_3::StoredVaultKey = from_json(&disk);
    let unsealed = release_n_plus_3::unseal(&stored, wrapping_key, &mut ctx)
        .expect("Release N+3 reads EncStrings");
    let disk = to_json(&release_n_plus_3::seal(unsealed, wrapping_key, &ctx));
    assert!(matches!(
        from_json::<release_n_plus_3::StoredVaultKey>(&disk).wrapped_key,
        LegacyCompatSymmetricKeyEnvelope::SymmetricKeyEnvelope(_)
    ));

    // Releases N to N+2 read the envelope.
    let stored: release_n::StoredVaultKey = from_json(&disk);
    let _vault_key =
        release_n::unseal(&stored, wrapping_key, &mut ctx).expect("Release N reads envelopes");

    // Releases before N cannot. This is the breaking change.
    let stored: before_migration::StoredVaultKey = from_json(&disk);
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
        VaultKey(LocalId),
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
