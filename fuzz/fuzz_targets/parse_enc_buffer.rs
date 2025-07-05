#![no_main]

use bitwarden_crypto::EncString;
use libfuzzer_sys::fuzz_target;

// EncBuffer parsing should never panic
fuzz_target!(|data: &[u8]| {
    let _ = EncString::from_buffer(data);
});
