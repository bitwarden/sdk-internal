//! Demonstrates wrapping secret values with [`Sensitive`] and [`SensitiveString`] so that
//! `Debug` and `Display` output is redacted by default.

use bitwarden_sensitive_value::{ExposeSensitive, Sensitive, SensitiveString};

fn main() {
    // `SensitiveString` is the FFI-friendly wrapper used for passwords, PINs, and similar
    // string-shaped secrets.
    let password: SensitiveString = SensitiveString::from("hunter2");

    // `Debug` and `Display` are redacted, so the secret is safe to log accidentally.
    #[cfg(not(feature = "dangerous-crypto-debug"))]
    assert_eq!(format!("{password:?}"), "[REDACTED]");
    #[cfg(not(feature = "dangerous-crypto-debug"))]
    assert_eq!(format!("{password}"), "[REDACTED]");

    // Explicitly borrow the secret when you need to use it.
    authenticate(password.expose());

    // The generic `Sensitive<T>` works for any type, not just strings. Here we wrap a
    // numeric token to prevent it from leaking into logs.
    let token: Sensitive<u64> = Sensitive::from(0xDEAD_BEEF_u64);
    #[cfg(not(feature = "dangerous-crypto-debug"))]
    assert_eq!(format!("{token:?}"), "[REDACTED]");

    // `expose_owned` consumes the wrapper and returns the underlying value.
    let raw = token.expose_owned();
    assert_eq!(raw, 0xDEAD_BEEF);
}

fn authenticate(password: &str) {
    // Pretend to verify the password against a stored hash.
    assert_eq!(password, "hunter2");
}
