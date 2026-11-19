//! Test-only key-slot IDs shared across this crate's unit tests.

use bitwarden_crypto::key_slot_ids;

key_slot_ids! {
    #[symmetric]
    pub enum TestSymmKey {
        #[local]
        Local(LocalId),
    }

    #[private]
    pub enum TestPrivateKey {
        #[local]
        Local(LocalId),
    }

    #[signing]
    pub enum TestSigningKey {
        #[local]
        Local(LocalId),
    }

    pub TestIds => TestSymmKey, TestPrivateKey, TestSigningKey;
}
