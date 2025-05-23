mod encryptable;
pub use encryptable::Encryptable;
mod decryptable;
pub use decryptable::Decryptable;

pub(crate) mod key_id;
pub use key_id::{KeyId, KeyIds};

/// Types implementing [IdentifyKey] are capable of knowing which cryptographic key is
/// needed to encrypt/decrypt them.
pub trait IdentifyKey<Key: KeyId> {
    fn key_identifier(&self) -> Key;
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::key_ids;
    key_ids! {
        #[symmetric]
        pub enum TestSymmKey {
            A(u8),

            // We only support one variant value,
            // but that value can be a tuple
            B((u8, u8)),

            #[local]
            C(uuid::Uuid),
        }

        #[asymmetric]
        pub enum TestAsymmKey {
            A(u8),
            B,
            #[local]
            C(uuid::Uuid),
        }

       pub TestIds => TestSymmKey, TestAsymmKey;
    }
}
