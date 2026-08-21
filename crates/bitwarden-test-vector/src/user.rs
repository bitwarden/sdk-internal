//! The user half of a test vector: identity, wrapped cryptographic state, unlock methods and the
//! raw key material

use std::collections::BTreeMap;

use bitwarden_core::{
    OrganizationId, UserId,
    key_management::{
        V2UpgradeToken, account_cryptographic_state::WrappedAccountCryptographicState,
        crypto::InitUserCryptoMethod,
    },
};
use bitwarden_crypto::{Kdf, UnsignedSharedKey};
use bitwarden_encoding::B64;
use serde::{Deserialize, Serialize};

use crate::{SchemaVersioned, VaultVector};

/// A single committed account test vector.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestVector {
    /// The on-disk schema version. Checked against [`crate::SCHEMA_VERSION`] on load.
    pub schema_version: u32,
    /// Stable slug identifying this vector, matching its file name.
    pub name: String,
    /// What this vector is for, in prose.
    pub description: String,
    /// The 32-byte seed handed to `bitwarden_random::set_seed_raw` when this vector was generated.
    /// Recorded so a regeneration can be reproduced exactly.
    pub rng_seed: B64,
    /// Identity, KDF and wrapped cryptographic state.
    pub account: AccountVector,
    /// Every unlock method this account supports, each one directly usable as the `method` of an
    /// [`InitUserCryptoRequest`].
    pub unlock_methods: Vec<InitUserCryptoMethod>,
    /// The key material the account is expected to yield once unlocked.
    pub raw_cryptographic_state: RawCryptographicStateVector,
    /// The account's vault, encrypted and decrypted.
    #[serde(default)]
    pub vault: VaultVector,
}

impl SchemaVersioned for TestVector {
    fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

/// Identity, KDF parameters and the wrapped cryptographic state of a test account.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountVector {
    /// The account's user id.
    pub user_id: UserId,
    /// The account's email, which doubles as the master-password KDF salt.
    pub email: String,
    /// The account's master password in the clear. These are throwaway test accounts.
    pub password: String,
    /// The KDF parameters the account's master password uses.
    pub kdf: Kdf,
    /// The security state version: `1` for a V1 account, `2` or higher for a V2 account.
    pub security_version: u64,
    /// The account keys, wrapped by the user key.
    pub account_cryptographic_state: WrappedAccountCryptographicState,
    /// Present only for an account mid-way through the V1 to V2 upgrade, where the unlock methods
    /// still yield the V1 user key but the cryptographic state and vault are already V2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade_token: Option<V2UpgradeToken>,
    /// The keys of the organizations this account is a member of, each sealed to the account's
    /// public key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub organization_keys: BTreeMap<OrganizationId, UnsignedSharedKey>,
}

/// The raw key material and key ids a vector's account is expected to hold once unlocked.
///
/// The three key types carry different notions of identity, and this struct records each one as it
/// actually exists rather than inventing a uniform id:
///
/// - Symmetric keys carry a COSE `kid`, but only for the COSE-serialized algorithms. An
///   `Aes256CbcHmac` user key — every V1 account — has none, so [`Self::user_key_id`] is `None`.
/// - RSA keys carry no key id at all. Their identity is the RFC 9679 COSE key thumbprint, recorded
///   as [`Self::key_pair_thumbprint`], which is equal for the private and public halves.
/// - Signing keys carry both a COSE `kid` and a thumbprint, so both are recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawCryptographicStateVector {
    /// The account symmetric key (user key), in the SDK's legacy key encoding.
    pub user_key: B64,
    /// The user key's COSE `kid`, hex encoded. `None` for `Aes256CbcHmac` keys, which carry none.
    pub user_key_id: Option<String>,
    /// The master key derived from the account's password and KDF. `None` when the account has no
    /// master password.
    pub master_key: Option<B64>,
    /// The account's private key, PKCS#8 DER.
    pub private_key: B64,
    /// The account's public key, SPKI DER.
    pub public_key: B64,
    /// The RFC 9679 COSE key thumbprint of the account's key pair, hex encoded.
    pub key_pair_thumbprint: String,
    /// The account's signing key, COSE encoded. `None` for a V1 account.
    pub signing_key: Option<B64>,
    /// The account's verifying key, COSE encoded. `None` for a V1 account.
    pub verifying_key: Option<B64>,
    /// The signing key's COSE `kid`, hex encoded. `None` for a V1 account.
    pub signing_key_id: Option<String>,
    /// The RFC 9679 COSE key thumbprint of the signing key, hex encoded. `None` for a V1 account.
    pub signing_key_thumbprint: Option<String>,
    /// The account's fingerprint phrase, computed over the user id and public key.
    pub fingerprint: String,
}
