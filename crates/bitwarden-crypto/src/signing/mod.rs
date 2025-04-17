/// Signing is domain-separated within bitwarden, to prevent cross protocol attacks.
///
/// A new signed entity or protocol shall use a new signing namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningNamespace {
    #[allow(dead_code)]
    EncryptionMetadata = 1,
    #[cfg(test)]
    Test = -1,
}

impl SigningNamespace {
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }
}
