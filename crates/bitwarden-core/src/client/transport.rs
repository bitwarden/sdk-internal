//! Transport settings for the SDK's HTTP clients: proxy and timeouts.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Network transport settings applied to the SDK's HTTP clients.
#[derive(Serialize, Deserialize, Debug, Clone, Default, JsonSchema)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TransportSettings {
    /// Proxy to route every SDK request through. `None` keeps the default behavior, which honors
    /// the standard proxy environment variables.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub proxy: Option<ProxySettings>,
    /// Overrides for the default request timeouts.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub timeouts: Option<TimeoutSettings>,
}

/// An HTTP proxy. HTTPS requests are tunneled through it with `CONNECT`.
// `Debug` is implemented by hand so the password never reaches a log line.
#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ProxySettings {
    /// Proxy URL, for example `http://proxy.example.com:3128`.
    pub url: String,
    /// Credentials sent to the proxy with HTTP Basic authentication.
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub credentials: Option<ProxyCredentials>,
    /// Comma-separated hosts, domains, and CIDR ranges that bypass the proxy, in the same format
    /// as the `NO_PROXY` environment variable.
    #[serde(default)]
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub no_proxy: Option<String>,
}

/// HTTP Basic credentials for a proxy.
// `Debug` is implemented by hand so the password never reaches a log line.
#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ProxyCredentials {
    /// Proxy username.
    pub username: String,
    /// Proxy password.
    pub password: String,
}

/// Request timeout overrides, in milliseconds. Unset fields keep the SDK defaults.
///
/// HTTP/2 pings and TCP keep-alive already close connections to a dead peer. A hung server on
/// HTTP/1.1 is only detected by `read_ms` or `request_ms`.
#[derive(Serialize, Deserialize, Debug, Clone, Default, JsonSchema)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TimeoutSettings {
    /// Maximum time to establish a connection, including the TLS handshake and any proxy tunnel.
    /// Defaults to 30 seconds.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub connect_ms: Option<u64>,
    /// Bounds the wait for the response headers, then each gap between response body chunks. It
    /// also caps the upload time, since it is not reset while the request body uploads. No
    /// default.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub read_ms: Option<u64>,
    /// Deadline for the whole request, from connecting until the response body is read. No
    /// default.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    pub request_ms: Option<u64>,
}

impl fmt::Debug for ProxySettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxySettings")
            .field("url", &redact_url(&self.url))
            .field("credentials", &self.credentials)
            .field("no_proxy", &self.no_proxy)
            .finish()
    }
}

impl fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Parses a proxy URL the way reqwest does: a URL without a scheme is read as `http://`.
fn parse_proxy_url(url: &str) -> Option<url::Url> {
    match url::Url::parse(url) {
        Ok(parsed) if parsed.has_host() => Some(parsed),
        Ok(_) | Err(url::ParseError::RelativeUrlWithoutBase) => {
            url::Url::parse(&format!("http://{url}")).ok()
        }
        Err(_) => None,
    }
}

/// Reduces a proxy URL to its scheme, host, and port, which drops any credentials. Anything that
/// does not parse is hidden entirely.
fn redact_url(url: &str) -> String {
    match parse_proxy_url(url)
        .as_ref()
        .and_then(|p| Some((p.scheme(), p.host_str()?, p.port())))
    {
        Some((scheme, host, Some(port))) => format!("{scheme}://{host}:{port}"),
        Some((scheme, host, None)) => format!("{scheme}://{host}"),
        None => "<redacted>".to_owned(),
    }
}

/// Builds every HTTP client of a [`Client`](crate::Client), so each one gets the transport
/// settings.
pub(crate) struct HttpClientFactory {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) transport: Option<TransportSettings>,
}

impl HttpClientFactory {
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn builder(&self) -> reqwest::ClientBuilder {
        apply_transport(
            bitwarden_api_base::new_http_client_builder(),
            self.transport.as_ref(),
        )
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn builder(&self) -> reqwest::ClientBuilder {
        bitwarden_api_base::new_http_client_builder()
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn apply_transport(
    mut builder: reqwest::ClientBuilder,
    transport: Option<&TransportSettings>,
) -> reqwest::ClientBuilder {
    if let Some(timeouts) = transport.and_then(|t| t.timeouts.as_ref()) {
        use std::time::Duration;

        if let Some(ms) = timeouts.connect_ms {
            builder = builder.connect_timeout(Duration::from_millis(ms));
        }
        if let Some(ms) = timeouts.read_ms {
            builder = builder.read_timeout(Duration::from_millis(ms));
        }
        if let Some(ms) = timeouts.request_ms {
            builder = builder.timeout(Duration::from_millis(ms));
        }
    }

    builder
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn proxy_with_secrets() -> ProxySettings {
        ProxySettings {
            url: "http://url-user:url-secret@proxy.example.com:3128".to_owned(),
            credentials: Some(ProxyCredentials {
                username: "user".to_owned(),
                password: "field-secret".to_owned(),
            }),
            no_proxy: Some("localhost".to_owned()),
        }
    }

    #[test]
    fn debug_redacts_proxy_passwords() {
        let settings = crate::ClientSettings {
            transport: Some(TransportSettings {
                proxy: Some(proxy_with_secrets()),
                timeouts: None,
            }),
            ..Default::default()
        };

        let debug = format!("{settings:?}");

        assert!(!debug.contains("field-secret"), "{debug}");
        assert!(!debug.contains("url-secret"), "{debug}");
        assert!(!debug.contains("url-user"), "{debug}");
        assert!(debug.contains("proxy.example.com:3128"), "{debug}");
        assert!(debug.contains("username: \"user\""), "{debug}");
    }

    #[test]
    fn debug_hides_unparseable_proxy_url() {
        let proxy = ProxySettings {
            url: "user:secret@not a url:port".to_owned(),
            credentials: None,
            no_proxy: None,
        };

        let debug = format!("{proxy:?}");

        assert!(!debug.contains("secret"), "{debug}");
    }

    #[test]
    fn debug_hides_proxy_url_that_reqwest_rejects() {
        let proxy = ProxySettings {
            url: "http://user:secret@proxy.example.com:notaport".to_owned(),
            credentials: None,
            no_proxy: None,
        };

        let debug = format!("{proxy:?}");

        assert!(!debug.contains("secret"), "{debug}");
    }

    #[test]
    fn debug_redacts_proxy_url_without_scheme() {
        let proxy = ProxySettings {
            url: "user:secret@proxy.example.com:3128".to_owned(),
            credentials: None,
            no_proxy: None,
        };

        let debug = format!("{proxy:?}");

        assert!(!debug.contains("secret"), "{debug}");
        assert!(debug.contains("proxy.example.com:3128"), "{debug}");
    }

    #[test]
    fn client_settings_without_transport_deserializes() {
        let settings: crate::ClientSettings =
            serde_json::from_str(r#"{"apiUrl": "https://api.example.com"}"#)
                .expect("settings should deserialize");

        assert!(settings.transport.is_none());
    }
}
