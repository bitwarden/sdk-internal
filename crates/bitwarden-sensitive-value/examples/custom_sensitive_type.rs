//! Demonstrates defining a custom, domain-named sensitive newtype around an integer. This is the
//! same pattern [`SensitiveString`] uses internally: a tuple struct wrapping [`Sensitive<T>`] with
//! [`ExposeSensitive`], `From`, and delegated `Debug`/`Display` impls so redaction is inherited.

use core::fmt;

use bitwarden_sensitive_value::{ExposeSensitive, Sensitive};

/// A custom sensitive wrapper around an account identifier. Naming the type makes intent clear at
/// call sites while keeping the value out of logs.
pub struct SensitiveAccountId(Sensitive<u64>);

impl From<u64> for SensitiveAccountId {
    fn from(value: u64) -> Self {
        Self(Sensitive::from(value))
    }
}

impl ExposeSensitive for SensitiveAccountId {
    type Exposed = u64;

    fn expose(&self) -> &Self::Exposed {
        self.0.expose()
    }

    fn expose_owned(self) -> Self::Exposed {
        self.0.expose_owned()
    }
}

// Delegating to the inner `Sensitive` means redaction is inherited for free.
impl fmt::Debug for SensitiveAccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for SensitiveAccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

fn main() {
    let account_id = SensitiveAccountId::from(1_234_567_890_u64);

    // `Debug` and `Display` are redacted, so the id is safe to log accidentally.
    #[cfg(not(feature = "dangerous-crypto-debug"))]
    assert_eq!(format!("{account_id:?}"), "[REDACTED]");
    #[cfg(not(feature = "dangerous-crypto-debug"))]
    assert_eq!(format!("{account_id}"), "[REDACTED]");

    // EXPOSE: We borrow the raw id only to hand it to a lookup helper that does not log it. This is
    // the boundary where the secret is intentionally used.
    lookup_account(*account_id.expose());

    // EXPOSE: Consume the wrapper to recover the underlying integer for the final assertion.
    let raw = account_id.expose_owned();
    assert_eq!(raw, 1_234_567_890);
}

fn lookup_account(id: u64) {
    // Pretend to look up the account by id.
    assert_eq!(id, 1_234_567_890);
}
