use rand::RngCore;
use uuid::Uuid;

const UUID_SEED_SIZE: usize = 16;

/// Since `KeyId` is a wrapper around UUIDs, this is statically 16 bytes.
pub(crate) const KEY_ID_SIZE: usize = 16;

/// A key id is a unique identifier for a single key. There is a 1:1 mapping between key ID and key
/// bytes, so something like a user key rotation is replacing the key with ID A with a new key with
/// ID B.
#[derive(Clone)]
pub(crate) struct KeyId(Uuid);

/// Fixed length identifiers for keys.
/// These are intended to be unique and constant per-key.
///
/// Currently these are randomly generated 16 byte identifiers, which is considered safe to randomly
/// generate with vanishingly small collision chance. However, the generation of IDs is an internal
/// concern and may change in the future.
impl KeyId {
    /// Creates a new random key ID randomly, sampled from the crates CSPRNG.
    pub fn make() -> Self {
        // We do not use the uuid crate's random generation functionality here to make sure the
        // entropy sampling aligns with the rest of this crates usage of CSPRNGs.
        let mut random_seed = [0u8; UUID_SEED_SIZE];
        rand::thread_rng().fill_bytes(&mut random_seed);

        let uuid = uuid::Builder::from_random_bytes(random_seed)
            .with_version(uuid::Version::Random)
            .with_variant(uuid::Variant::RFC4122);
        Self(uuid.into_uuid())
    }
}

impl From<KeyId> for [u8; KEY_ID_SIZE] {
    fn from(key_id: KeyId) -> Self {
        key_id.0.into_bytes()
    }
}

impl From<&KeyId> for Vec<u8> {
    fn from(key_id: &KeyId) -> Self {
        key_id.0.as_bytes().to_vec()
    }
}

impl From<[u8; KEY_ID_SIZE]> for KeyId {
    fn from(bytes: [u8; KEY_ID_SIZE]) -> Self {
        KeyId(Uuid::from_bytes(bytes))
    }
}

impl std::fmt::Debug for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyId({})", self.0)
    }
}
