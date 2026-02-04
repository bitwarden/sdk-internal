use serde::{Deserialize, Serialize};

/// Server communication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ServerCommunicationConfig {
    /// Bootstrap configuration determining how to establish server communication
    pub bootstrap: BootstrapConfig,
}

/// Bootstrap configuration for server communication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum BootstrapConfig {
    /// Direct connection with no special authentication requirements
    Direct,
    /// SSO cookie vendor configuration for load balancer authentication
    SsoCookieVendor(SsoCookieVendorConfig),
}

/// SSO cookie vendor configuration
///
/// This configuration is provided by the server.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SsoCookieVendorConfig {
    /// Identity provider login URL for browser redirect during bootstrap
    pub idp_login_url: String,
    /// Cookie name
    pub cookie_name: String,
    /// Cookie domain for validation
    pub cookie_domain: String,
    /// Cookie value shards
    ///
    /// IdP cookies can be sharded across multiple values. When present, all shards
    /// should be concatenated when setting the cookie for HTTP requests.
    pub cookie_value: Option<Vec<String>>,
}

// We manually implement Debug to make sure we don't print sensitive cookie values
impl std::fmt::Debug for SsoCookieVendorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoCookieVendorConfig")
            .field("idp_login_url", &self.idp_login_url)
            .field("cookie_name", &self.cookie_name)
            .field("cookie_domain", &self.cookie_domain)
            .field("cookie_value", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_bootstrap_serialization() {
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::Direct,
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"direct\""));

        let deserialized: ServerCommunicationConfig = serde_json::from_str(&json).unwrap();
        assert!(matches!(deserialized.bootstrap, BootstrapConfig::Direct));
    }

    #[test]
    fn sso_cookie_vendor_serialization() {
        let config = ServerCommunicationConfig {
            bootstrap: BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
                idp_login_url: "https://timeloop-auth.acme.com/login".to_string(),
                cookie_name: "ALBAuthSessionCookie".to_string(),
                cookie_domain: "vault.example.com".to_string(),
                cookie_value: None,
            }),
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"ssoCookieVendor\""));
        assert!(json.contains("timeloop-auth.acme.com"));
        assert!(json.contains("ALBAuthSessionCookie"));

        let deserialized: ServerCommunicationConfig = serde_json::from_str(&json).unwrap();
        if let BootstrapConfig::SsoCookieVendor(vendor_config) = deserialized.bootstrap {
            assert_eq!(
                vendor_config.idp_login_url,
                "https://timeloop-auth.acme.com/login"
            );
            assert_eq!(vendor_config.cookie_name, "ALBAuthSessionCookie");
            assert_eq!(vendor_config.cookie_domain, "vault.example.com");
            assert!(vendor_config.cookie_value.is_none());
        } else {
            panic!("Expected SsoCookieVendor variant");
        }
    }

    #[test]
    fn cookie_value_some_and_none() {
        // Test with None
        let config_none = SsoCookieVendorConfig {
            idp_login_url: "https://example.com".to_string(),
            cookie_name: "TestCookie".to_string(),
            cookie_domain: "example.com".to_string(),
            cookie_value: None,
        };

        let json_none = serde_json::to_string(&config_none).unwrap();
        let deserialized_none: SsoCookieVendorConfig = serde_json::from_str(&json_none).unwrap();
        assert!(deserialized_none.cookie_value.is_none());

        // Test with Some - single shard
        let config_some = SsoCookieVendorConfig {
            idp_login_url: "https://example.com".to_string(),
            cookie_name: "TestCookie".to_string(),
            cookie_domain: "example.com".to_string(),
            cookie_value: Some(vec!["eyJhbGciOiJFUzI1NiIsImtpZCI6Im...".to_string()]),
        };

        let json_some = serde_json::to_string(&config_some).unwrap();
        let deserialized_some: SsoCookieVendorConfig = serde_json::from_str(&json_some).unwrap();
        assert_eq!(
            deserialized_some.cookie_value,
            Some(vec!["eyJhbGciOiJFUzI1NiIsImtpZCI6Im...".to_string()])
        );

        // Test with multiple shards
        let config_sharded = SsoCookieVendorConfig {
            idp_login_url: "https://example.com".to_string(),
            cookie_name: "TestCookie".to_string(),
            cookie_domain: "example.com".to_string(),
            cookie_value: Some(vec![
                "shard1".to_string(),
                "shard2".to_string(),
                "shard3".to_string(),
            ]),
        };

        let json_sharded = serde_json::to_string(&config_sharded).unwrap();
        let deserialized_sharded: SsoCookieVendorConfig =
            serde_json::from_str(&json_sharded).unwrap();
        assert_eq!(
            deserialized_sharded.cookie_value,
            Some(vec![
                "shard1".to_string(),
                "shard2".to_string(),
                "shard3".to_string()
            ])
        );
    }

    #[test]
    fn enum_variants() {
        let direct = BootstrapConfig::Direct;
        assert!(matches!(direct, BootstrapConfig::Direct));

        let vendor = BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
            idp_login_url: "https://example.com".to_string(),
            cookie_name: "Cookie".to_string(),
            cookie_domain: "example.com".to_string(),
            cookie_value: None,
        });
        assert!(matches!(vendor, BootstrapConfig::SsoCookieVendor(_)));
    }

    #[test]
    fn debug_output_redacts_cookie_value() {
        // Test that cookie values are not exposed in Debug output
        let config_with_cookie = SsoCookieVendorConfig {
            idp_login_url: "https://example.com/login".to_string(),
            cookie_name: "SessionCookie".to_string(),
            cookie_domain: "example.com".to_string(),
            cookie_value: Some(vec!["super-secret-cookie-value-abc123".to_string()]),
        };

        let debug_output = format!("{:?}", config_with_cookie);

        // Should contain non-sensitive fields
        assert!(debug_output.contains("SsoCookieVendorConfig"));
        assert!(debug_output.contains("example.com/login"));
        assert!(debug_output.contains("SessionCookie"));
        assert!(debug_output.contains("example.com"));

        // Should NOT contain the actual cookie value
        assert!(!debug_output.contains("super-secret-cookie-value-abc123"));
        // Should show redaction marker
        assert!(debug_output.contains("[REDACTED]"));
    }
}
