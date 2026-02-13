use rand::Rng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Since `KeyId` is a wrapper around UUIDs, this is statically 16 bytes.
pub(crate) const KEY_ID_SIZE: usize = 16;

/// A key id is a unique identifier for a single key. There is a 1:1 mapping between key ID and key
/// bytes, so something like a user key rotation is replacing the key with ID A with a new key with
/// ID B.
#[derive(Clone, PartialEq, Zeroize)]
pub struct KeyId([u8; KEY_ID_SIZE]);

impl ConstantTimeEq for KeyId {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Fixed length identifiers for keys.
/// These are intended to be unique and constant per-key.
///
/// Currently these are randomly generated 16 byte identifiers, which is considered safe to randomly
/// generate with vanishingly small collision chance. However, the generation of IDs is an internal
/// concern and may change in the future.
impl KeyId {
    /// Creates a new random key ID randomly, sampled from the crates CSPRNG.
    pub fn make() -> Self {
        let mut rng = rand::thread_rng();
        let mut key_id = [0u8; KEY_ID_SIZE];
        rng.fill(&mut key_id);
        Self(key_id)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for KeyId {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != KEY_ID_SIZE {
            return Err("Invalid length for KeyId");
        }
        let mut key_id = [0u8; KEY_ID_SIZE];
        key_id.copy_from_slice(value);
        Ok(Self(key_id))
    }
}

impl From<KeyId> for [u8; KEY_ID_SIZE] {
    fn from(key_id: KeyId) -> Self {
        key_id.0
    }
}

impl From<&KeyId> for Vec<u8> {
    fn from(key_id: &KeyId) -> Self {
        key_id.0.as_slice().to_vec()
    }
}

impl From<[u8; KEY_ID_SIZE]> for KeyId {
    fn from(bytes: [u8; KEY_ID_SIZE]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Debug for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyId({})", hex::encode(self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_key_id_debug() {
        let key_id = KeyId::make();
        println!("{:?}", key_id);
    }
}
