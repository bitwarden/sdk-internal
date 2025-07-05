#![no_main]

use bitwarden_fido::try_from_credential_full_view;
use bitwarden_vault::Fido2CredentialFullView;
use libfuzzer_sys::fuzz_target;

// EncString parsing should never panic
fuzz_target!(|data: Fido2CredentialFullView| {
    let _ = try_from_credential_full_view(data);
});
