#![no_main]

use std::str::FromStr;

use bitwarden_crypto::UnsignedSharedKey;
use libfuzzer_sys::fuzz_target;

// UnsignedSharedKey parsing should never panic
fuzz_target!(|data: &[u8]| {
    let data_string = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = UnsignedSharedKey::from_str(data_string);
});
