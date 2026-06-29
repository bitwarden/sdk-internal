use crate::Kdf;

/// The set of cryptographic algorithms a [`super::KeyStore`] is allowed to use, determined by the
/// environment it operates in.
///
/// It is set once when the store is constructed (see [`super::KeyStore::set_cipher_suite`]) and
/// read through [`super::KeyStoreContext`] by operations that must pick a compliant algorithm, such
/// as the KDF for a new account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherSuite {
    /// The default suite, using the modern recommended algorithms (e.g. Argon2id).
    #[default]
    Standard,
    /// The FIPS-compliant suite required in government (FedRAMP) environments, restricted to
    /// FIPS-approved algorithms (e.g. PBKDF2).
    Fips,
}

impl CipherSuite {
    /// Returns the [`CipherSuite`] for the current environment, given whether the client is in
    /// Gov Mode (FedRAMP).
    pub fn from_gov_mode(gov_mode: bool) -> Self {
        if gov_mode {
            CipherSuite::Fips
        } else {
            CipherSuite::Standard
        }
    }

    /// Returns the KDF a new account should use under this suite.
    ///
    /// [`CipherSuite::Fips`] uses the FIPS-approved PBKDF2; [`CipherSuite::Standard`] uses the
    /// modern Argon2id default.
    pub fn default_kdf_for_new_account(self) -> Kdf {
        match self {
            CipherSuite::Standard => Kdf::default_argon2(),
            CipherSuite::Fips => Kdf::default_pbkdf2(),
        }
    }

    /// Returns whether the given KDF is allowed under this suite.
    ///
    /// Under [`CipherSuite::Fips`] only PBKDF2 is FIPS-approved; under [`CipherSuite::Standard`]
    /// every supported KDF is allowed.
    pub fn is_kdf_compliant(self, kdf: &Kdf) -> bool {
        match self {
            CipherSuite::Standard => true,
            CipherSuite::Fips => matches!(kdf, Kdf::PBKDF2 { .. }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_standard() {
        assert_eq!(CipherSuite::default(), CipherSuite::Standard);
    }

    #[test]
    fn from_gov_mode_maps_to_suite() {
        assert_eq!(CipherSuite::from_gov_mode(false), CipherSuite::Standard);
        assert_eq!(CipherSuite::from_gov_mode(true), CipherSuite::Fips);
    }

    #[test]
    fn standard_uses_argon2_for_new_account() {
        assert!(matches!(
            CipherSuite::Standard.default_kdf_for_new_account(),
            Kdf::Argon2id { .. }
        ));
    }

    #[test]
    fn fips_uses_pbkdf2_for_new_account() {
        assert!(matches!(
            CipherSuite::Fips.default_kdf_for_new_account(),
            Kdf::PBKDF2 { .. }
        ));
    }

    #[test]
    fn standard_allows_any_kdf() {
        assert!(CipherSuite::Standard.is_kdf_compliant(&Kdf::default_argon2()));
        assert!(CipherSuite::Standard.is_kdf_compliant(&Kdf::default_pbkdf2()));
    }

    #[test]
    fn fips_allows_only_pbkdf2() {
        assert!(CipherSuite::Fips.is_kdf_compliant(&Kdf::default_pbkdf2()));
        assert!(!CipherSuite::Fips.is_kdf_compliant(&Kdf::default_argon2()));
    }
}
