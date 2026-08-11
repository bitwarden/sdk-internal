use crate::client::internal::InternalClient;

/// Returns true when the client is in Gov Mode.
///
/// Today, this is inferred from the configured API URL host. Uses URL parsing
/// rather than substring matching so that paths, queries,
/// and adversarial subdomain spoofs (e.g. api.bitwarden-gov.com.evil.example)
/// cannot accidentally classify as Gov. Host matching is case-insensitive and
/// allows any subdomain under bitwarden-gov.com.
///
/// PM-36520 will refactor this to read from stored /config state, adding
/// support for self-hosted Gov installs where URL inference cannot work
/// because self-hosted URLs are customer-chosen.
pub(crate) fn is_gov_mode(internal: &InternalClient) -> bool {
    url::Url::parse(&internal.api_configurations.api_config.base_path)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase))
        .map(|h| h == "bitwarden-gov.com" || h.ends_with(".bitwarden-gov.com"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use crate::{Client, ClientSettings};

    fn gov_mode_for(url: &str) -> bool {
        Client::new(Some(ClientSettings {
            api_url: url.into(),
            ..Default::default()
        }))
        .gov_mode()
    }

    #[test]
    fn true_for_canonical_gov_host() {
        assert!(gov_mode_for("https://api.bitwarden-gov.com"));
    }

    #[test]
    fn true_for_alternate_subdomain_on_gov_domain() {
        assert!(gov_mode_for("https://vault.bitwarden-gov.com"));
    }

    #[test]
    fn false_for_us_and_eu_hosts() {
        assert!(!gov_mode_for("https://api.bitwarden.com"));
        assert!(!gov_mode_for("https://api.bitwarden.eu"));
    }

    #[test]
    fn false_for_self_hosted_with_bitwarden_in_name() {
        assert!(!gov_mode_for("https://bitwarden.example.com/api"));
        assert!(!gov_mode_for("https://my-bitwarden.eu/api"));
    }

    #[test]
    fn false_for_spoofed_subdomain() {
        assert!(!gov_mode_for("https://api.bitwarden-gov.com.evil.example/"));
        assert!(!gov_mode_for("https://bitwarden-gov.com.evil.example/"));
    }

    #[test]
    fn false_for_path_only_match() {
        assert!(!gov_mode_for("https://example.com/bitwarden-gov.com/api"));
    }

    #[test]
    fn case_insensitive() {
        assert!(gov_mode_for("https://API.BITWARDEN-GOV.COM"));
    }

    #[test]
    fn false_for_invalid_url() {
        assert!(!gov_mode_for("not a url"));
        assert!(!gov_mode_for(""));
    }
}
