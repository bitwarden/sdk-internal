mod encryptable;
pub(crate) use encryptable::PrimitiveEncryptableWithContentType;
pub use encryptable::{CompositeEncryptable, PrimitiveEncryptable};
mod decryptable;
pub use decryptable::Decryptable;

pub(crate) mod key_id;
pub use key_id::{KeyId, KeyIds, LocalId};

/// Types implementing [IdentifyKey] are capable of knowing which cryptographic key is
/// needed to encrypt/decrypt them.
pub trait IdentifyKey<Key: KeyId> {
    #[expect(missing_docs)]
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
            C(LocalId),
        }

        #[asymmetric]
        pub enum TestAsymmKey {
            A(u8),
            B,
            #[local]
            C(LocalId),
        }

        #[signing]
        pub enum TestSigningKey {
            A(u8),
            B,
            #[local]
            C(LocalId),
        }

       pub TestIds => TestSymmKey, TestAsymmKey, TestSigningKey;
    }
}
