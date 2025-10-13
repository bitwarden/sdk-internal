use std::collections::HashMap;

use bitwarden_core::Client;
use futures::{StreamExt, TryStreamExt, stream};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::cipher_risk::{CipherLoginDetails, CipherRisk, CipherRiskOptions, PasswordReuseMap};
use crate::CipherRiskError;

/// Client for evaluating credential risk for login ciphers.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct CipherRiskClient {
    pub(crate) client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CipherRiskClient {
    /// Build password reuse map for a list of login ciphers.
    ///
    /// Returns a map where keys are passwords and values are the number of times
    /// each password appears in the provided list. This map can be passed to `compute_risk()`
    /// to enable password reuse detection.
    pub fn password_reuse_map(
        &self,
        login_details: Vec<CipherLoginDetails>,
    ) -> Result<PasswordReuseMap, CipherRiskError> {
        let mut map = HashMap::new();
        for details in login_details {
            if !details.password.is_empty() {
                *map.entry(details.password).or_insert(0) += 1;
            }
        }
        Ok(PasswordReuseMap { map })
    }

    /// Evaluate security risks for multiple login ciphers concurrently.
    ///
    /// For each cipher:
    /// 1. Calculates password strength (0-4) using zxcvbn with cipher-specific context
    /// 2. Optionally checks if the password has been exposed via Have I Been Pwned API
    /// 3. Counts how many times the password is reused across the provided ciphers
    ///
    /// Returns a vector of `CipherRisk` results, one for each input cipher.
    ///
    /// # Errors
    ///
    /// Returns `CipherRiskError::Reqwest` if HIBP API requests fail when `check_exposed` is
    /// enabled. Network errors include timeouts, connection failures, HTTP errors, or rate
    /// limiting. On error, the entire operation fails - no partial results are returned.
    pub async fn compute_risk(
        &self,
        login_details: Vec<CipherLoginDetails>,
        options: CipherRiskOptions,
    ) -> Result<Vec<CipherRisk>, CipherRiskError> {
        // Create futures that can run concurrently
        let futures = login_details.into_iter().map(|details| {
            let http_client = self.client.internal.get_http_client().clone();
            let password_map = options.password_map.clone();
            let base_url = options
                .hibp_base_url
                .clone()
                .unwrap_or_else(|| "https://api.pwnedpasswords.com".to_string());

            async move {
                let password_strength = Self::calculate_password_strength(
                    &details.password,
                    details.username.as_deref(),
                );

                // Check exposure via HIBP API if enabled
                // Network errors now propagate up instead of being silently ignored
                let exposed_count = if options.check_exposed {
                    Some(
                        Self::check_password_exposed(&http_client, &details.password, &base_url)
                            .await?,
                    )
                } else {
                    None
                };

                // Check reuse from provided map (default to 1 if not in map)
                let reuse_count = password_map
                    .as_ref()
                    .and_then(|reuse_map| reuse_map.map.get(&details.password))
                    .copied()
                    .unwrap_or(1);

                Ok::<CipherRisk, CipherRiskError>(CipherRisk {
                    id: details.id,
                    password_strength,
                    exposed_count,
                    reuse_count,
                })
            }
        });

        // Process up to 100 futures concurrently, fail fast on first error
        let results: Vec<CipherRisk> = stream::iter(futures)
            .buffer_unordered(100)
            .try_collect()
            .await?;

        Ok(results)
    }

    /// Calculate password strength with cipher-specific context.
    ///
    /// Uses zxcvbn to score password strength from 0 (weakest) to 4 (strongest).
    /// Penalizes passwords that contain parts of the username/email.
    fn calculate_password_strength(password: &str, username: Option<&str>) -> u8 {
        let mut user_inputs = Vec::new();

        // Extract meaningful parts from username field
        if let Some(username) = username {
            user_inputs.extend(Self::extract_user_inputs(username));
        }

        // Call zxcvbn with cipher-specific inputs only (no "bitwarden" globals)
        let inputs_refs: Vec<&str> = user_inputs.iter().map(|s| s.as_str()).collect();
        zxcvbn::zxcvbn(password, &inputs_refs).score().into()
    }

    /// Extract meaningful tokens from username/email for password penalization.
    ///
    /// Handles both email addresses and plain usernames:
    /// - For emails: extracts and tokenizes the local part (before @)
    /// - For usernames: tokenizes the entire string
    /// - Splits on non-alphanumeric characters and converts to lowercase
    fn extract_user_inputs(username: &str) -> Vec<String> {
        // Check if it's email-like (contains @)
        if let Some((local_part, _domain)) = username.split_once('@') {
            // Email: extract local part tokens
            local_part
                .trim()
                .to_lowercase()
                .split(|c: char| !c.is_alphanumeric())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        } else {
            // Username: split on non-alphanumeric
            username
                .trim()
                .to_lowercase()
                .split(|c: char| !c.is_alphanumeric())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        }
    }

    /// Hash password with SHA-1 and split into prefix/suffix for k-anonymity.
    ///
    /// Returns a tuple of (prefix: first 5 chars, suffix: remaining chars).
    fn hash_password_for_hibp(password: &str) -> (String, String) {
        use sha1::{Digest, Sha1};

        let hash = Sha1::digest(password.as_bytes());
        let hash_hex = format!("{:X}", hash);
        let (prefix, suffix) = hash_hex.split_at(5);
        (prefix.to_string(), suffix.to_string())
    }

    /// Parse HIBP API response to find password hash and return breach count.
    ///
    /// Response format: "SUFFIX:COUNT\r\n..." (e.g.,
    /// "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n...").
    /// Returns the number of times the password appears in breaches (0 if not found).
    fn parse_hibp_response(response: &str, target_suffix: &str) -> u32 {
        for line in response.lines() {
            if let Some((hash_suffix, count_str)) = line.split_once(':') {
                if hash_suffix.eq_ignore_ascii_case(target_suffix) {
                    return count_str.trim().parse().unwrap_or(0);
                }
            }
        }
        0
    }

    /// Check password exposure via HIBP API using k-anonymity model.
    ///
    /// Implements k-anonymity to ensure privacy:
    /// 1. Hash password with SHA-1
    /// 2. Send only first 5 characters of hash to HIBP API
    /// 3. API returns all hash suffixes matching that prefix
    /// 4. Check locally if full hash exists in results
    ///
    /// This ensures the actual password never leaves the client.
    /// Returns the number of times the password appears in HIBP database (0 if not found).
    async fn check_password_exposed(
        http_client: &reqwest::Client,
        password: &str,
        hibp_base_url: &str,
    ) -> Result<u32, CipherRiskError> {
        let (prefix, suffix) = Self::hash_password_for_hibp(password);

        // Query HIBP API with prefix only (k-anonymity)
        let url = format!("{}/range/{}", hibp_base_url, prefix);
        let response = http_client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        Ok(Self::parse_hibp_response(&response, &suffix))
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account;

    use super::*;

    #[test]
    fn test_extract_user_inputs_from_email() {
        let inputs = CipherRiskClient::extract_user_inputs("john.doe@example.com");
        assert_eq!(inputs, vec!["john", "doe"]);
    }

    #[test]
    fn test_extract_user_inputs_from_username() {
        let inputs = CipherRiskClient::extract_user_inputs("john_doe123");
        assert_eq!(inputs, vec!["john", "doe123"]);
    }

    #[test]
    fn test_extract_user_inputs_lowercase() {
        let inputs = CipherRiskClient::extract_user_inputs("JohnDoe@Example.COM");
        assert_eq!(inputs, vec!["johndoe"]);
    }

    #[test]
    fn test_extract_user_inputs_empty() {
        let inputs = CipherRiskClient::extract_user_inputs("");
        assert!(inputs.is_empty());
    }

    #[tokio::test]
    async fn test_password_reuse_map() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let risk_client = CipherRiskClient {
            client: client.clone(),
        };

        let login_details = vec![
            CipherLoginDetails {
                id: None,
                password: "password123".to_string(),
                username: Some("user1".to_string()),
            },
            CipherLoginDetails {
                id: None,
                password: "password123".to_string(),
                username: Some("user2".to_string()),
            },
            CipherLoginDetails {
                id: None,
                password: "unique_password".to_string(),
                username: Some("user3".to_string()),
            },
        ];

        let password_map = risk_client.password_reuse_map(login_details).unwrap();

        assert_eq!(password_map.map.get("password123"), Some(&2));
        assert_eq!(password_map.map.get("unique_password"), Some(&1));
    }

    #[tokio::test]
    async fn test_calculate_password_strength_weak() {
        let strength = CipherRiskClient::calculate_password_strength("password", None);
        assert!(strength <= 1, "Expected weak password, got {}", strength);
    }

    #[tokio::test]
    async fn test_calculate_password_strength_strong() {
        let strength = CipherRiskClient::calculate_password_strength("xK9#mP$2qL@7vN&4wR", None);
        assert!(strength >= 3, "Expected strong password, got {}", strength);
    }

    #[tokio::test]
    async fn test_calculate_password_strength_penalizes_username() {
        // Password containing username should be weaker
        let strength_with_username =
            CipherRiskClient::calculate_password_strength("johndoe123!", Some("johndoe"));
        let strength_without_username =
            CipherRiskClient::calculate_password_strength("johndoe123!", None);

        assert!(
            strength_with_username <= strength_without_username,
            "Password should be weaker when it contains username"
        );
    }

    #[tokio::test]
    async fn test_compute_risk_without_hibp() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let risk_client = CipherRiskClient {
            client: client.clone(),
        };

        let login_details = vec![
            CipherLoginDetails {
                id: None,
                password: "password123".to_string(),
                username: Some("user1".to_string()),
            },
            CipherLoginDetails {
                id: None,
                password: "password123".to_string(),
                username: Some("user2".to_string()),
            },
        ];

        let password_map = risk_client
            .password_reuse_map(login_details.clone())
            .unwrap();

        let options = CipherRiskOptions {
            password_map: Some(password_map),
            check_exposed: false,
            hibp_base_url: None,
        };

        let risks = risk_client
            .compute_risk(login_details, options)
            .await
            .unwrap();

        assert_eq!(risks.len(), 2);
        assert_eq!(risks[0].reuse_count, 2);
        assert_eq!(risks[1].reuse_count, 2);
        assert!(risks[0].exposed_count.is_none());
        assert!(risks[1].exposed_count.is_none());
    }

    #[tokio::test]
    async fn test_password_reuse_map_empty_passwords() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let risk_client = CipherRiskClient {
            client: client.clone(),
        };

        let login_details = vec![
            CipherLoginDetails {
                id: None,
                password: "".to_string(),
                username: Some("user1".to_string()),
            },
            CipherLoginDetails {
                id: None,
                password: "valid_password".to_string(),
                username: Some("user2".to_string()),
            },
        ];

        let password_map = risk_client.password_reuse_map(login_details).unwrap();

        // Empty passwords should not be in the map
        assert!(password_map.map.get("").is_none());
        assert_eq!(password_map.map.get("valid_password"), Some(&1));
    }

    #[test]
    fn test_hash_password_for_hibp() {
        // Test with a known password: "password"
        // SHA-1 hash of "password" is: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = CipherRiskClient::hash_password_for_hibp("password");

        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");

        // Validate expected lengths (5 for prefix, 35 for suffix = 40 total SHA-1 hex)
        assert_eq!(prefix.len(), 5);
        assert_eq!(suffix.len(), 35);
    }

    #[test]
    fn test_parse_hibp_response_found() {
        // Simulate real HIBP API response format with the target password
        let mock_response = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:6\r\n\
                            0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n\
                            00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n";

        let target_suffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

        let count = CipherRiskClient::parse_hibp_response(mock_response, target_suffix);

        assert_eq!(count, 6);
    }

    #[test]
    fn test_parse_hibp_response_not_found() {
        // Simulate HIBP API response without target hash
        let mock_response = "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n\
                            00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n\
                            011053FD0102E94D6AE2F8B83D76FAF94F6:1\r\n";

        let target_suffix = "NOTFOUNDNOTFOUNDNOTFOUNDNOTFOUND";

        let count = CipherRiskClient::parse_hibp_response(mock_response, target_suffix);

        assert_eq!(count, 0);
    }

    #[test]
    fn test_parse_hibp_response_case_insensitive() {
        // HIBP API returns uppercase hashes, but we should match case-insensitively
        let mock_response = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\r\n";

        // Test with lowercase suffix
        let target_suffix_lower = "1e4c9b93f3f0682250b6cf8331b7ee68fd8";

        let count = CipherRiskClient::parse_hibp_response(mock_response, target_suffix_lower);

        assert_eq!(count, 12345);
    }

    #[test]
    fn test_parse_hibp_response_multiple_matches() {
        // Response with multiple hashes, target is in the middle
        let mock_response = "AAA111:100\r\n\
                            BBB222:200\r\n\
                            CCC333:300\r\n\
                            DDD444:400\r\n";

        let count = CipherRiskClient::parse_hibp_response(mock_response, "CCC333");
        assert_eq!(count, 300);
    }

    #[test]
    fn test_parse_hibp_response_empty() {
        // Empty response
        let mock_response = "";

        let count = CipherRiskClient::parse_hibp_response(mock_response, "ANYTHING");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_parse_hibp_response_malformed_count() {
        // Response with invalid count (should return 0 on parse failure)
        let mock_response = "AAA111:not_a_number\r\n";

        let count = CipherRiskClient::parse_hibp_response(mock_response, "AAA111");
        assert_eq!(count, 0);
    }

    // Wiremock tests for actual HIBP API integration
    #[tokio::test]
    async fn test_hibp_api_password_found() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        let server = MockServer::start().await;

        // Mock HIBP API response for "password" (hash: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8)
        Mock::given(method("GET"))
            .and(path("/range/5BAA6"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n\
                     0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n\
                     00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n",
            ))
            .mount(&server)
            .await;

        let result = CipherRiskClient::check_password_exposed(
            &reqwest::Client::new(),
            "password",
            &server.uri(),
        )
        .await
        .unwrap();

        assert_eq!(result, 3861493);
    }

    #[tokio::test]
    async fn test_hibp_api_password_not_found() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        let server = MockServer::start().await;

        // Mock HIBP API response that doesn't contain our password
        Mock::given(method("GET"))
            .and(path("/range/A94A8"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n\
                     00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n\
                     011053FD0102E94D6AE2F8B83D76FAF94F6:1\r\n",
            ))
            .mount(&server)
            .await;

        // "test" hashes to A94A8FE5CCB19BA61C4C0873D391E987982FBBD3
        let result = CipherRiskClient::check_password_exposed(
            &reqwest::Client::new(),
            "test",
            &server.uri(),
        )
        .await
        .unwrap();

        assert_eq!(result, 0);
    }

    #[tokio::test]
    async fn test_hibp_api_network_error() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        let server = MockServer::start().await;

        // Mock network error (500 status)
        Mock::given(method("GET"))
            .and(path("/range/5BAA6"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let result = CipherRiskClient::check_password_exposed(
            &reqwest::Client::new(),
            "password",
            &server.uri(),
        )
        .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CipherRiskError::Reqwest(_)));
    }

    #[tokio::test]
    async fn test_compute_risk_propagates_network_errors() {
        // Test that network errors from HIBP API are properly propagated
        // instead of being silently swallowed
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path_regex},
        };

        let server = MockServer::start().await;

        // Mock network error (500 status) for all HIBP range requests
        Mock::given(method("GET"))
            .and(path_regex(r"^/range/[A-F0-9]{5}$"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let risk_client = CipherRiskClient { client };

        let login_details = vec![CipherLoginDetails {
            id: None,
            password: "password123".to_string(),
            username: Some("user1".to_string()),
        }];

        let options = CipherRiskOptions {
            password_map: None,
            check_exposed: true, // Enable HIBP checking
            hibp_base_url: Some(server.uri()),
        };

        let result = risk_client.compute_risk(login_details, options).await;

        // Verify error is propagated, not swallowed
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, CipherRiskError::Reqwest(_)),
            "Expected CipherRiskError::Reqwest, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn test_compute_risk_integration() {
        // Integration test verifying the full compute_risk flow
        // This tests compute_risk without HIBP (check_exposed=false) to avoid
        // network calls and test stability issues
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let risk_client = CipherRiskClient {
            client: client.clone(),
        };

        let login_details = vec![
            CipherLoginDetails {
                id: None,
                password: "weak".to_string(),
                username: Some("user1".to_string()),
            },
            CipherLoginDetails {
                id: None,
                password: "xK9#mP$2qL@7vN&4wR".to_string(),
                username: Some("user2".to_string()),
            },
        ];

        let password_map = risk_client
            .password_reuse_map(login_details.clone())
            .unwrap();

        let options = CipherRiskOptions {
            password_map: Some(password_map),
            check_exposed: false,
            hibp_base_url: None,
        };

        let results = risk_client
            .compute_risk(login_details, options)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);

        // Weak password should have low strength
        assert!(
            results[0].password_strength <= 1,
            "Expected weak password strength, got {}",
            results[0].password_strength
        );

        // Strong password should have high strength
        assert!(
            results[1].password_strength >= 3,
            "Expected strong password strength, got {}",
            results[1].password_strength
        );

        // Both passwords used once
        assert_eq!(results[0].reuse_count, 1);
        assert_eq!(results[1].reuse_count, 1);

        // HIBP not checked
        assert!(results[0].exposed_count.is_none());
        assert!(results[1].exposed_count.is_none());
    }

    #[tokio::test]
    async fn test_compute_risk_concurrent_requests() {
        // This test verifies that compute_risk truly executes requests concurrently
        // by tracking request timestamps. If concurrent, multiple requests arrive
        // within a short time window. If sequential, requests are spaced out.
        use std::{
            sync::{Arc, Mutex},
            time::{Duration, Instant},
        };

        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path_regex},
        };

        let server = MockServer::start().await;

        // Track when each request arrives
        let request_times = Arc::new(Mutex::new(Vec::new()));

        // Mock HIBP API that records request times
        Mock::given(method("GET"))
            .and(path_regex(r"^/range/[A-F0-9]{5}$"))
            .respond_with({
                let request_times = request_times.clone();
                move |_req: &wiremock::Request| {
                    // Record the time this request arrived
                    request_times.lock().unwrap().push(Instant::now());

                    ResponseTemplate::new(200)
                        .set_body_string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\n")
                        .set_delay(Duration::from_millis(10))
                }
            })
            .mount(&server)
            .await;

        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let risk_client = CipherRiskClient { client };

        // Create 5 different passwords to ensure different hash prefixes
        // This forces 5 separate API calls
        let login_details: Vec<CipherLoginDetails> = (0..5)
            .map(|i| CipherLoginDetails {
                id: None,
                password: format!("password{}", i),
                username: Some(format!("user{}", i)),
            })
            .collect();

        let options = CipherRiskOptions {
            password_map: None,
            check_exposed: true, // Enable HIBP checking to test concurrency
            hibp_base_url: Some(server.uri()), // Use mock server URL
        };

        let results = risk_client
            .compute_risk(login_details, options)
            .await
            .unwrap();

        // Verify all results were returned
        assert_eq!(results.len(), 5);

        // Verify all passwords were checked
        for result in &results {
            assert!(result.exposed_count.is_some());
        }

        // Prove concurrency by analyzing request arrival times
        // If truly concurrent, all 5 requests should arrive within a very short window (< 5ms
        // window) If sequential with 10ms delays, they'd be spread over 40-50ms
        let times = request_times.lock().unwrap();
        let first = times[0];
        let last = times[times.len() - 1];
        let time_span = last.duration_since(first);

        assert!(
            time_span < Duration::from_millis(5),
            "Expected concurrent execution (all requests within 5ms), \
             but requests were spread over {}ms. This suggests requests \
             are being made sequentially instead of concurrently.",
            time_span.as_millis()
        );
    }
}
