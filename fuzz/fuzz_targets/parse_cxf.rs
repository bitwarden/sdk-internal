#![no_main]

use bitwarden_exporters::parse_cxf;
use libfuzzer_sys::fuzz_target;

// SymmetricCryptoKey parsing should never panic
fuzz_target!(|data: &[u8]| {
    let payload = match String::from_utf8(data.to_vec()) {
        Ok(s) => s,
        Err(_) => return, // Skip invalid UTF-8 data
    };
    let _ = parse_cxf(payload);
});

