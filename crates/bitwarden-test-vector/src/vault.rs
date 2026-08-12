//! The vault half of a test vector: the account's ciphers, folders and sends, each in both its
//! encrypted and decrypted form.

use std::collections::BTreeMap;

use bitwarden_collections::collection::{Collection, CollectionView};
use bitwarden_encoding::B64;
use bitwarden_send::{Send, SendView};
use bitwarden_vault::{Cipher, CipherView, Folder, FolderView};
use serde::{Deserialize, Serialize};

/// The vault half of a test vector.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
pub struct VaultVector {
    /// The account's ciphers.
    pub ciphers: Vec<CipherVectorItem>,
    /// The account's folders.
    pub folders: Vec<VectorItem<Folder, FolderView>>,
    /// The account's sends.
    pub sends: Vec<VectorItem<Send, SendView>>,
    /// The organization's collections.
    ///
    /// Only ever populated on an organization vector: a collection is keyed to
    /// [`SymmetricKeySlotId::Organization`], so a personal vault cannot hold one.
    pub collections: Vec<VectorItem<Collection, CollectionView>>,
}

/// One vault item, in both its encrypted and decrypted form.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VectorItem<Enc, Dec> {
    /// The item's id, duplicated out of the models so a failure can be attributed without parsing.
    pub id: String,
    /// The item as the server stores it.
    pub encrypted: Enc,
    /// The item as it decrypts under the account's user key.
    pub decrypted: Dec,
}

/// One cipher, in both forms, plus the per-item key material it is expected to yield.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CipherVectorItem {
    /// The cipher's id.
    pub id: String,
    /// Whether this cipher's data is sealed as a blob rather than field-encrypted.
    ///
    /// Recorded explicitly so a test can assert on the format without reimplementing
    /// `Cipher::is_blob_encrypted`. Always `true` for a V2 account's own ciphers, always `false`
    /// for a V1 account's and for organization ciphers.
    pub blob_encrypted: bool,
    /// The cipher as the server stores it.
    pub encrypted: Cipher,
    /// The cipher as it decrypts under the account's user key.
    pub decrypted: CipherView,
    /// The per-item keys this cipher wraps.
    pub keys: CipherKeysVector,
}

/// The per-item key material of a cipher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CipherKeysVector {
    /// The cipher's per-item key, in the SDK's legacy key encoding. `None` for a keyless legacy
    /// cipher, whose fields are encrypted directly under the user key.
    pub cipher_key: Option<B64>,
    /// The cipher key's COSE `kid`, hex encoded, or `None` if the algorithm carries none.
    pub cipher_key_id: Option<String>,
    /// The cipher's attachment keys, by attachment id. A `BTreeMap` so the serialized order is
    /// stable.
    #[serde(default)]
    pub attachments: BTreeMap<String, AttachmentKeysVector>,
}

/// The key material of one attachment, and which of the three historical layouts it uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttachmentKeysVector {
    /// Which encryption layout this attachment uses.
    pub version: AttachmentVersion,
    /// The per-attachment content key, in the SDK's legacy key encoding. `None` for v0 and v1.
    pub key: Option<B64>,
    /// The attachment key's COSE `kid`, hex encoded, or `None` if there is no key or the algorithm
    /// carries none.
    pub key_id: Option<String>,
}

/// The three historical attachment encryption layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttachmentVersion {
    /// No attachment key and no cipher key: contents are encrypted directly under the user key.
    V0,
    /// No attachment key, but the cipher has a per-item key: contents are under the cipher key.
    V1,
    /// A per-attachment content key, wrapped by the cipher key.
    V2,
}
