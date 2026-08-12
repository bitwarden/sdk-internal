//! The 1Password sign-in region.

/// A 1Password sign-in region, or a custom Enterprise sign-in address. Determines the API host.
#[derive(Debug, Clone)]
pub enum Region {
    /// `my.1password.com`, the default.
    Global,
    /// `my.1password.eu`.
    Europe,
    /// `my.1password.ca`.
    Canada,
    /// A custom Enterprise sign-in address.
    Custom(String),
}

impl Region {
    /// The API host for this region.
    pub fn domain(&self) -> &str {
        match self {
            Region::Global => "my.1password.com",
            Region::Europe => "my.1password.eu",
            Region::Canada => "my.1password.ca",
            Region::Custom(domain) => domain,
        }
    }

    /// Interprets a region shorthand (`global`/`eu`/`ca`) or a full custom sign-in domain.
    pub fn parse(value: &str) -> Region {
        match value.to_lowercase().as_str() {
            "global" | "com" | "us" | "my.1password.com" => Region::Global,
            "europe" | "eu" | "my.1password.eu" => Region::Europe,
            "canada" | "ca" | "my.1password.ca" => Region::Canada,
            _ => Region::Custom(value.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_maps_to_domain() {
        assert_eq!(Region::Global.domain(), "my.1password.com");
        assert_eq!(Region::Europe.domain(), "my.1password.eu");
        assert_eq!(Region::Canada.domain(), "my.1password.ca");
        assert_eq!(
            Region::Custom("my.company.1password.com".into()).domain(),
            "my.company.1password.com"
        );
    }

    #[test]
    fn region_parses_shorthands_and_custom_domains() {
        assert!(matches!(Region::parse("eu"), Region::Europe));
        assert!(matches!(Region::parse("Canada"), Region::Canada));
        assert!(matches!(Region::parse("com"), Region::Global));
        assert!(matches!(
            Region::parse("acme.1password.com"),
            Region::Custom(_)
        ));
    }
}
