#![no_main]

use bitwarden_crypto::SymmetricCryptoKey;
use libfuzzer_sys::fuzz_target;

// SymmetricCryptoKey parsing should never panic
fuzz_target!(|data: &[u8]| {
    let _ = SymmetricCryptoKey::try_from(data.to_vec());
});
