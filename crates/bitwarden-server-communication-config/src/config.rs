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
#[serde(rename_all = "camelCase")]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SsoCookieVendorConfig {
    /// Identity provider login URL for browser redirect during bootstrap
    pub idp_login_url: Option<String>,
    /// Cookie name (base name, without shard suffix)
    pub cookie_name: Option<String>,
    /// Cookie domain for validation
    pub cookie_domain: Option<String>,
    /// Acquired cookies
    ///
    /// For sharded cookies, this contains multiple entries with names like
    /// `AWSELBAuthSessionCookie-0`, `AWSELBAuthSessionCookie-1`, etc.
    /// For unsharded cookies, this contains a single entry with the base name.
    pub cookie_value: Option<Vec<crate::AcquiredCookie>>,
}

// We manually implement Debug to make sure we don't print sensitive cookie values
impl std::fmt::Debug for SsoCookieVendorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsoCookieVendorConfig")
            .field("idp_login_url", &self.idp_login_url)
            .field("cookie_name", &self.cookie_name)
            .field("cookie_domain", &self.cookie_domain)
            .field(
                "cookie_value",
                &self.cookie_value.as_ref().map(|_| "[REDACTED]"),
            )
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
                idp_login_url: Some("https://timeloop-auth.acme.com/login".to_string()),
                cookie_name: Some("ALBAuthSessionCookie".to_string()),
                cookie_domain: Some("vault.example.com".to_string()),
                cookie_value: None,
            }),
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"ssoCookieVendor\""));
        assert!(json.contains("timeloop-auth.acme.com"));
        assert!(json.contains("ALBAuthSessionCookie"));

        // Verify SDK can parse server JSON with camelCase fields
        let server_json = r#"{"bootstrap":{"type":"ssoCookieVendor","idpLoginUrl":"https://idp.example.com/login","cookieName":"TestCookie","cookieDomain":"example.com"}}"#;
        let parsed = serde_json::from_str::<ServerCommunicationConfig>(server_json).unwrap();
        if let BootstrapConfig::SsoCookieVendor(vendor) = parsed.bootstrap {
            assert_eq!(
                vendor.idp_login_url,
                Some("https://idp.example.com/login".to_string())
            );
            assert_eq!(vendor.cookie_name, Some("TestCookie".to_string()));
            assert_eq!(vendor.cookie_domain, Some("example.com".to_string()));
        } else {
            panic!("Expected SsoCookieVendor variant");
        }

        let deserialized: ServerCommunicationConfig = serde_json::from_str(&json).unwrap();
        if let BootstrapConfig::SsoCookieVendor(vendor_config) = deserialized.bootstrap {
            assert_eq!(
                vendor_config.idp_login_url,
                Some("https://timeloop-auth.acme.com/login".to_string())
            );
            assert_eq!(
                vendor_config.cookie_name,
                Some("ALBAuthSessionCookie".to_string())
            );
            assert_eq!(
                vendor_config.cookie_domain,
                Some("vault.example.com".to_string())
            );
            assert!(vendor_config.cookie_value.is_none());
        } else {
            panic!("Expected SsoCookieVendor variant");
        }
    }

    #[test]
    fn cookie_value_some_and_none() {
        use crate::AcquiredCookie;

        // Test with None
        let config_none = SsoCookieVendorConfig {
            idp_login_url: Some("https://example.com".to_string()),
            cookie_name: Some("TestCookie".to_string()),
            cookie_domain: Some("example.com".to_string()),
            cookie_value: None,
        };

        let json_none = serde_json::to_string(&config_none).unwrap();
        let deserialized_none: SsoCookieVendorConfig = serde_json::from_str(&json_none).unwrap();
        assert!(deserialized_none.cookie_value.is_none());

        // Test with Some - single cookie
        let config_some = SsoCookieVendorConfig {
            idp_login_url: Some("https://example.com".to_string()),
            cookie_name: Some("TestCookie".to_string()),
            cookie_domain: Some("example.com".to_string()),
            cookie_value: Some(vec![AcquiredCookie {
                name: "TestCookie".to_string(),
                value: "eyJhbGciOiJFUzI1NiIsImtpZCI6Im...".to_string(),
            }]),
        };

        let json_some = serde_json::to_string(&config_some).unwrap();
        let deserialized_some: SsoCookieVendorConfig = serde_json::from_str(&json_some).unwrap();
        assert_eq!(deserialized_some.cookie_value.as_ref().unwrap().len(), 1);
        assert_eq!(
            deserialized_some.cookie_value.as_ref().unwrap()[0].name,
            "TestCookie"
        );

        // Test with multiple shards
        let config_sharded = SsoCookieVendorConfig {
            idp_login_url: Some("https://example.com".to_string()),
            cookie_name: Some("TestCookie".to_string()),
            cookie_domain: Some("example.com".to_string()),
            cookie_value: Some(vec![
                AcquiredCookie {
                    name: "TestCookie-0".to_string(),
                    value: "shard1".to_string(),
                },
                AcquiredCookie {
                    name: "TestCookie-1".to_string(),
                    value: "shard2".to_string(),
                },
                AcquiredCookie {
                    name: "TestCookie-2".to_string(),
                    value: "shard3".to_string(),
                },
            ]),
        };

        let json_sharded = serde_json::to_string(&config_sharded).unwrap();
        let deserialized_sharded: SsoCookieVendorConfig =
            serde_json::from_str(&json_sharded).unwrap();
        assert_eq!(deserialized_sharded.cookie_value.as_ref().unwrap().len(), 3);
        assert_eq!(
            deserialized_sharded.cookie_value.as_ref().unwrap()[0].name,
            "TestCookie-0"
        );
    }

    #[test]
    fn enum_variants() {
        let direct = BootstrapConfig::Direct;
        assert!(matches!(direct, BootstrapConfig::Direct));

        let vendor = BootstrapConfig::SsoCookieVendor(SsoCookieVendorConfig {
            idp_login_url: Some("https://example.com".to_string()),
            cookie_name: Some("Cookie".to_string()),
            cookie_domain: Some("example.com".to_string()),
            cookie_value: None,
        });
        assert!(matches!(vendor, BootstrapConfig::SsoCookieVendor(_)));
    }

    #[test]
    fn debug_output_redacts_cookie_value() {
        use crate::AcquiredCookie;

        // Test that cookie values are not exposed in Debug output
        let config_with_cookie = SsoCookieVendorConfig {
            idp_login_url: Some("https://example.com/login".to_string()),
            cookie_name: Some("SessionCookie".to_string()),
            cookie_domain: Some("example.com".to_string()),
            cookie_value: Some(vec![AcquiredCookie {
                name: "SessionCookie".to_string(),
                value: "super-secret-cookie-value-abc123".to_string(),
            }]),
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
