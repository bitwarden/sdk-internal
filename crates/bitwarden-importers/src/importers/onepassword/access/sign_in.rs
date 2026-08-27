//! The sign-in address an account lives at: its subdomain and one of 1Password's domains.

use std::fmt;

use super::error::OnePasswordError;

/// The longest a DNS label may be.
const MAX_SUBDOMAIN_LENGTH: usize = 63;

/// One of the domains 1Password serves accounts on, the set its clients offer in the sign-in form.
///
/// The first three are regions, each storing its accounts in a different jurisdiction; an account
/// belongs to exactly one of them. Enterprise accounts sit on their own domain instead.
///
/// See <https://support.1password.com/regions/>.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
/// closed set, so only the subdomain needs checking, and [`SignInAddress::new`] is the only way to
/// build one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignInAddress {
    subdomain: String,
    domain: SignInDomain,
}

impl SignInAddress {
    /// Builds an address from an account subdomain, rejecting anything that is not a DNS label.
    ///
    /// The subdomain is trimmed and lowercased first, so what a user typed into a sign-in form
    /// goes through unchanged.
    pub fn new(subdomain: &str, domain: SignInDomain) -> Result<SignInAddress, OnePasswordError> {
        let subdomain = subdomain.trim().to_lowercase();
        validate_subdomain(&subdomain)?;

        Ok(SignInAddress { subdomain, domain })
    }

    /// The domain half of the address.
    pub fn domain(&self) -> SignInDomain {
        self.domain
    }
}

impl fmt::Display for SignInAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.subdomain, self.domain.as_str())
    }
}

/// Rejects a subdomain that is not a DNS label, which is what keeps a stray `/`, `@` or `?` from
/// pointing the whole session at another host.
fn validate_subdomain(subdomain: &str) -> Result<(), OnePasswordError> {
    let invalid = |reason: &str| {
        Err(OnePasswordError::Internal(format!(
            "invalid subdomain '{subdomain}': {reason}"
        )))
    };

    if subdomain.is_empty() {
        return invalid("it is empty");
    }
    if subdomain.len() > MAX_SUBDOMAIN_LENGTH {
        return invalid(&format!(
            "it is longer than {MAX_SUBDOMAIN_LENGTH} characters"
        ));
    }
    if !subdomain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return invalid("only letters, digits and dashes are allowed");
    }
    if subdomain.starts_with('-') || subdomain.ends_with('-') {
        return invalid("it starts or ends with a dash");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(subdomain: &str) -> Result<SignInAddress, OnePasswordError> {
        SignInAddress::new(subdomain, SignInDomain::Global)
    }

    #[test]
    fn address_joins_the_subdomain_and_the_domain() {
        for (domain, expected) in [
            (SignInDomain::Global, "my.1password.com"),
            (SignInDomain::Europe, "my.1password.eu"),
            (SignInDomain::Canada, "my.1password.ca"),
            (SignInDomain::Enterprise, "my.ent.1password.com"),
        ] {
            let address = SignInAddress::new("my", domain).expect("a valid subdomain");
            assert_eq!(address.to_string(), expected);
            assert_eq!(address.domain(), domain);
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
                error.to_string().contains("invalid subdomain"),
                "unexpected error for '{subdomain}': {error}"
            );
        }
    }

    #[test]
    fn address_accepts_the_longest_label() {
        address(&"m".repeat(MAX_SUBDOMAIN_LENGTH)).expect("63 characters is a valid label");
    }
}
