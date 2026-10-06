//! The sign-in address an account lives at: its subdomain and one of 1Password's domains.

use std::fmt;

use super::error::OnePasswordError;

/// The longest a DNS label may be.
const MAX_SUBDOMAIN_LENGTH: usize = 63;

/// One of the domains 1Password serves accounts on, as offered in its sign-in form.
///
/// The first three are regions, each storing its accounts in a different jurisdiction; an account
/// belongs to exactly one of them. Enterprise accounts sit on their own domain instead.
///
/// See <https://support.1password.com/regions/>.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify)
)]
pub enum SignInDomain {
    /// `1password.com`, the default. Data hosted in the United States.
    Global,
    /// `1password.eu`. Data hosted in the European Union.
    Europe,
    /// `1password.ca`. Data hosted in Canada.
    Canada,
    /// `ent.1password.com`, for 1Password Enterprise.
    Enterprise,
}

impl SignInDomain {
    /// The domain on its own, without an account subdomain.
    pub fn as_str(&self) -> &'static str {
        match self {
            SignInDomain::Global => "1password.com",
            SignInDomain::Europe => "1password.eu",
            SignInDomain::Canada => "1password.ca",
            SignInDomain::Enterprise => "ent.1password.com",
        }
    }
}

/// Where an account signs in, such as `my.1password.com`.
///
/// An individual account uses `my`; a team or business account uses its own name. The domain is a
/// closed set, so only the subdomain needs checking. The access client normalizes and validates the
/// record before using it because foreign bindings construct records directly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(serde::Serialize, serde::Deserialize, tsify::Tsify)
)]
pub struct SignInAddress {
    /// The account-specific DNS label, such as `my`.
    pub subdomain: String,
    /// The 1Password domain on which the account is hosted.
    pub domain: SignInDomain,
}

impl SignInAddress {
    pub(crate) fn normalize(&mut self) -> Result<(), OnePasswordError> {
        self.subdomain = self.subdomain.trim().to_lowercase();
        self.validate()
    }

    fn validate(&self) -> Result<(), OnePasswordError> {
        let invalid = |reason: &str| {
            Err(OnePasswordError::InvalidSignInAddress(format!(
                "subdomain '{}': {reason}",
                self.subdomain
            )))
        };

        if self.subdomain.is_empty() {
            return invalid("it is empty");
        }
        if self.subdomain.len() > MAX_SUBDOMAIN_LENGTH {
            return invalid(&format!(
                "it is longer than {MAX_SUBDOMAIN_LENGTH} characters"
            ));
        }
        if !self
            .subdomain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return invalid("only letters, digits and dashes are allowed");
        }
        if self.subdomain.starts_with('-') || self.subdomain.ends_with('-') {
            return invalid("it starts or ends with a dash");
        }

        Ok(())
    }
}

impl fmt::Display for SignInAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.subdomain, self.domain.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(subdomain: &str) -> Result<SignInAddress, OnePasswordError> {
        let mut address = SignInAddress {
            subdomain: subdomain.into(),
            domain: SignInDomain::Global,
        };
        address.normalize()?;
        Ok(address)
    }

    #[test]
    fn address_joins_the_subdomain_and_the_domain() {
        for (domain, expected) in [
            (SignInDomain::Global, "my.1password.com"),
            (SignInDomain::Europe, "my.1password.eu"),
            (SignInDomain::Canada, "my.1password.ca"),
            (SignInDomain::Enterprise, "my.ent.1password.com"),
        ] {
            let address = SignInAddress {
                subdomain: "my".into(),
                domain,
            };
            assert_eq!(address.to_string(), expected);
            assert_eq!(address.domain, domain);
        }
    }

    #[test]
    fn address_cleans_up_the_subdomain() {
        assert_eq!(
            address("  ACME-Team \n")
                .expect("a valid subdomain")
                .to_string(),
            "acme-team.1password.com"
        );
    }

    /// Each of these would otherwise point the session at a host of the input's choosing.
    #[test]
    fn address_rejects_a_subdomain_that_is_not_a_label() {
        for subdomain in [
            "",
            "   ",
            "my.1password.com",
            "evil.com/x",
            "my@evil.com",
            "my?x=",
            "my#x",
            "my team",
            "-my",
            "my-",
            &"m".repeat(MAX_SUBDOMAIN_LENGTH + 1),
        ] {
            let error = address(subdomain).expect_err("not a DNS label");
            assert!(
                matches!(&error, OnePasswordError::InvalidSignInAddress(_)),
                "unexpected error for '{subdomain}': {error}"
            );
        }
    }

    #[test]
    fn address_accepts_the_longest_label() {
        address(&"m".repeat(MAX_SUBDOMAIN_LENGTH)).expect("63 characters is a valid label");
    }

    #[test]
    fn address_constructed_as_a_record_is_still_validated() {
        let mut address = SignInAddress {
            subdomain: "evil.com/x".into(),
            domain: SignInDomain::Global,
        };

        assert!(matches!(
            address.normalize(),
            Err(OnePasswordError::InvalidSignInAddress(_))
        ));
    }
}
