mod encryptable;
pub(crate) use encryptable::PrimitiveEncryptableWithContentType;
pub use encryptable::{CompositeEncryptable, PrimitiveEncryptable};
mod decryptable;
pub use decryptable::Decryptable;

pub(crate) mod keyslot_ids;
pub use keyslot_ids::{KeySlotId, KeySlotIds, LocalId};

/// Types implementing [IdentifyKey] are capable of knowing which cryptographic key is
/// needed to encrypt/decrypt them.
pub trait IdentifyKey<Key: KeySlotId> {
    #[allow(missing_docs)]
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

        #[private]
        pub enum TestPrivateKey {
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

       pub TestIds => TestSymmKey, TestPrivateKey, TestSigningKey;
    }
}
