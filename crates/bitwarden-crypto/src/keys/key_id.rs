use rand::RngCore;

#[derive(Clone, Debug, PartialEq, Eq, zeroize::ZeroizeOnDrop)]
pub(crate) struct KeyId([u8; 24]);

/// Fixed length identifiers for keys.
/// These are intended to be unique and constant per-key.
///
/// Currently these are randomly generated 24 byte identifiers, which is considered safe to randomly
/// generate with vanishingly small collision chance. However, the generation of IDs is an internal
/// concern and may change in the future.
impl KeyId {
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 24]) -> Self {
        KeyId(bytes)
    }

    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let mut key_id = [0u8; 24];
        rng.fill_bytes(&mut key_id);
        Self::from_bytes(key_id)
    }
}

impl TryFrom<&[u8]> for KeyId {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let key_id = <[u8; 24]>::try_from(value)?;
        Ok(Self::from_bytes(key_id))
    }
}
