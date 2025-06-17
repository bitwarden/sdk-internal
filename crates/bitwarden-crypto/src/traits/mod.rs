mod encryptable;
pub use encryptable::Encryptable;
mod decryptable;
pub use decryptable::Decryptable;

pub(crate) mod key_id;
pub use key_id::{KeyId, KeyIds};

/// Types implementing [IdentifyKey] are capable of knowing which cryptographic key is
/// needed to encrypt/decrypt them.
pub trait IdentifyKey<Key: KeyId> {
    #[allow(missing_docs)]
    fn key_identifier(&self) -> Key;
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::key_ids;
    key_ids! {
        #[symmetric]
        pub enum TestSymmKey {
            A(u32),

            // We only support one variant value,
            // but that value can be a tuple
            B((u8, u8)),

            #[local]
            C(u16),
        }

        #[asymmetric]
        pub enum TestAsymmKey {
            A(u16),
            B,
            #[local]
            C(&'static str),
        }

        #[signing]
        pub enum TestSigningKey {
            A(u8),
            B,
            #[local]
            C(&'static str),
        }

       pub TestIds => TestSymmKey, TestAsymmKey, TestSigningKey;
    }
}
