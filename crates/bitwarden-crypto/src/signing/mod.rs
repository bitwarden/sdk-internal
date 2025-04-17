/// Signing is domain-separated within bitwarden, to prevent cross protocol attacks.
///
/// A new signed entity or protocol shall use a new signing namespace. Further, signing
/// namespaces cannot be renamed, since that would invalidate signatures.
#[derive(strum_macros::Display, strum_macros::EnumString)]
pub enum SigningNamespace {
    EncryptionMetadata,
    #[cfg(test)]
    Test,
}
