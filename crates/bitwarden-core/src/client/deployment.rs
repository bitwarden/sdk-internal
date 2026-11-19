use bitwarden_crypto::CipherSuite;

use crate::client::{gov_mode::is_gov_mode, internal::InternalClient};

/// Cloud domains operated by Bitwarden, outside Gov.
const CLOUD_DOMAINS: [&str; 2] = ["bitwarden.com", "bitwarden.eu"];

/// Where the server the client talks to is hosted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Deployment {
    /// Bitwarden cloud (US or EU).
    Cloud,
    /// Bitwarden Gov cloud (FedRAMP).
    Gov,
    /// Any server not hosted by Bitwarden.
    SelfHosted,
}

impl Deployment {
    /// Returns the [`CipherSuite`] the deployment must use.
    ///
    /// Gov and self-hosted deployments use FIPS-approved algorithms (e.g. PBKDF2); cloud uses the
    /// modern defaults (e.g. Argon2id).
    pub(crate) fn cipher_suite(self) -> CipherSuite {
        match self {
            Deployment::Cloud => CipherSuite::Standard,
            Deployment::Gov | Deployment::SelfHosted => CipherSuite::Fips,
        }
    }
}

/// Returns the [`Deployment`] inferred from the configured API URL host.
///
/// Hosts on, or under, a [`CLOUD_DOMAINS`] entry are cloud; Gov hosts per [`is_gov_mode`]; any
/// other host, or an unparsable URL, is self-hosted.
pub(crate) fn deployment(internal: &InternalClient) -> Deployment {
    if is_gov_mode(internal) {
        return Deployment::Gov;
    }

    let host = url::Url::parse(&internal.api_configurations.api_config.base_path)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase));
    let Some(host) = host else {
        return Deployment::SelfHosted;
    };

    // Match the domain itself or a subdomain, e.g. `api.bitwarden.com`, but not
    // `bitwarden.com.evil.example` or `mybitwarden.com`.
    let is_cloud = CLOUD_DOMAINS
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")));
    if is_cloud {
        return Deployment::Cloud;
    }

    Deployment::SelfHosted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Client, ClientSettings};

    fn deployment_for(url: &str) -> Deployment {
        let client = Client::new(Some(ClientSettings {
            api_url: url.into(),
            ..Default::default()
        }));
        deployment(&client.internal)
    }

    #[test]
    fn cloud_for_us_and_eu_hosts() {
        assert_eq!(
            deployment_for("https://api.bitwarden.com"),
            Deployment::Cloud
        );
        assert_eq!(
            deployment_for("https://api.bitwarden.eu"),
            Deployment::Cloud
        );
        assert_eq!(
            deployment_for("https://API.BITWARDEN.COM"),
            Deployment::Cloud
        );
    }

    #[test]
    fn gov_for_gov_host() {
        assert_eq!(
            deployment_for("https://api.bitwarden-gov.com"),
            Deployment::Gov
        );
    }

    #[test]
    fn self_hosted_for_other_hosts() {
        assert_eq!(
            deployment_for("https://bitwarden.example.com/api"),
            Deployment::SelfHosted
        );
        assert_eq!(
            deployment_for("http://localhost:4000"),
            Deployment::SelfHosted
        );
    }

    #[test]
    fn self_hosted_for_spoofed_cloud_hosts() {
        assert_eq!(
            deployment_for("https://api.bitwarden.com.evil.example"),
            Deployment::SelfHosted
        );
        assert_eq!(
            deployment_for("https://mybitwarden.com"),
            Deployment::SelfHosted
        );
        assert_eq!(
            deployment_for("https://example.com/bitwarden.com/api"),
            Deployment::SelfHosted
        );
    }

    #[test]
    fn self_hosted_for_invalid_url() {
        assert_eq!(deployment_for("not a url"), Deployment::SelfHosted);
    }

    #[test]
    fn cipher_suite_is_fips_outside_cloud() {
        assert_eq!(Deployment::Cloud.cipher_suite(), CipherSuite::Standard);
        assert_eq!(Deployment::Gov.cipher_suite(), CipherSuite::Fips);
        assert_eq!(Deployment::SelfHosted.cipher_suite(), CipherSuite::Fips);
    }
}
