#![no_main]

use bitwarden_crypto::generate_mac;
use libfuzzer_sys::fuzz_target;

// EncString parsing should never panic
fuzz_target!(|data: &[u8]| {
    let _ = generate_mac(data, &[], &[]);
});
