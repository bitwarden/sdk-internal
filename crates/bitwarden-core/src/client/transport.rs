//! Transport-level client configuration (proxy + timeouts).
//!
//! Transport-level configuration (proxy + timeouts) for PM-38470. These types
//! are threaded through [`crate::ClientSettings`] and applied at HTTP client
//! construction via [`apply_transport`]. Per O5 the mTLS cert chain is NOT a
//! field here.

#[cfg(not(feature = "wasm"))]
use schemars::JsonSchema;
#[cfg(not(feature = "wasm"))]
use serde::{Deserialize, Serialize};

/// Optional transport-level settings (proxy + timeouts) applied to the SDK's
/// HTTP clients. Absent on WASM, where the browser/Node fetch backend owns
/// transport configuration.
#[cfg(not(feature = "wasm"))]
#[derive(Serialize, Deserialize, Debug, Clone, Default, JsonSchema)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TransportSettings {
    /// Optional proxy configuration.
    pub proxy: Option<ProxySettings>,
    /// Optional timeout configuration.
    pub timeouts: Option<TimeoutSettings>,
}

// No derived Debug on the proxy types: ClientSettings derives Debug, so the new
// `transport` field is printed transitively. Hand-written masking Debug impls close that.
/// Proxy configuration.
#[cfg(not(feature = "wasm"))]
#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ProxySettings {
    /// Proxy URL. May itself embed userinfo credentials, which are masked in `Debug`.
    pub url: String,
    /// Optional proxy authentication credentials.
    pub credentials: Option<ProxyCredentials>,
    /// Optional comma-separated no-proxy list.
    pub no_proxy: Option<String>,
}

/// Proxy authentication credentials.
#[cfg(not(feature = "wasm"))]
#[derive(Serialize, Deserialize, Clone, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ProxyCredentials {
    /// Proxy username.
    pub username: String,
    /// Proxy password. Masked in `Debug`.
    pub password: String,
}

/// Per-request timeout configuration, in milliseconds.
#[cfg(not(feature = "wasm"))]
#[derive(Serialize, Deserialize, Debug, Clone, Default, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TimeoutSettings {
    /// Connect timeout, in milliseconds.
    pub connect_ms: Option<u64>,
    /// Read timeout, in milliseconds.
    pub read_ms: Option<u64>,
    /// Total request timeout, in milliseconds.
    pub request_ms: Option<u64>,
}

// Credential-safe Debug impls
#[cfg(not(feature = "wasm"))]
impl std::fmt::Debug for ProxyCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[cfg(not(feature = "wasm"))]
impl std::fmt::Debug for ProxySettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_url = reqwest::Url::parse(&self.url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_else(|| "<redacted>".to_owned());
        f.debug_struct("ProxySettings")
            .field("url", &redacted_url)
            .field("credentials", &self.credentials)
            .field("no_proxy", &self.no_proxy)
            .finish()
    }
}

#[cfg(all(test, not(feature = "wasm")))]
mod tests {
    use super::*;

    #[test]
    fn debug_masks_proxy_credentials_password() {
        let creds = ProxyCredentials {
            username: "alice".to_owned(),
            password: "hunter2".to_owned(),
        };
        let rendered = format!("{creds:?}");
        assert!(rendered.contains("alice"));
        assert!(!rendered.contains("hunter2"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn debug_masks_proxy_url_userinfo_and_credentials() {
        let proxy = ProxySettings {
            url: "https://user:secret@proxy.example.com:8080/path".to_owned(),
            credentials: Some(ProxyCredentials {
                username: "bob".to_owned(),
                password: "topsecret".to_owned(),
            }),
            no_proxy: Some("localhost".to_owned()),
        };
        let rendered = format!("{proxy:?}");
        // URL userinfo is dropped; only the host survives.
        assert!(rendered.contains("proxy.example.com"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("user:secret"));
        // Nested credential password stays masked.
        assert!(!rendered.contains("topsecret"));
    }
}

/// Apply transport settings to a [`reqwest::ClientBuilder`].
///
/// Applies timeout overrides from [`TransportSettings`] on top of the factory
/// defaults. mTLS lands in Task 4.
///
/// Gated on both predicates: it makes reqwest calls (so not on the wasm32 target)
/// and it references [`TransportSettings`] (which the `wasm` feature omits).
#[cfg(all(not(target_arch = "wasm32"), not(feature = "wasm")))]
pub(crate) fn apply_transport(
    mut builder: reqwest::ClientBuilder,
    transport: Option<&TransportSettings>,
) -> reqwest::Result<reqwest::ClientBuilder> {
    use std::time::Duration;

    if let Some(t) = transport.and_then(|s| s.timeouts.as_ref()) {
        if let Some(ms) = t.connect_ms {
            builder = builder.connect_timeout(Duration::from_millis(ms));
        }
        if let Some(ms) = t.read_ms {
            builder = builder.read_timeout(Duration::from_millis(ms));
        }
        if let Some(ms) = t.request_ms {
            builder = builder.timeout(Duration::from_millis(ms));
        }
    }

    if let Some(p) = transport.and_then(|s| s.proxy.as_ref()) {
        let mut proxy = reqwest::Proxy::all(&p.url)?;
        if let Some(c) = &p.credentials {
            proxy = proxy.basic_auth(&c.username, &c.password);
        }
        if let Some(list) = &p.no_proxy {
            proxy = proxy.no_proxy(reqwest::NoProxy::from_string(list));
        }
        builder = builder.proxy(proxy);
    }

    Ok(builder)
}
