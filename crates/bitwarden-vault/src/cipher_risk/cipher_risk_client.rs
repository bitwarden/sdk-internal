use std::sync::Arc;

use bitwarden_core::Client;
use bitwarden_error::bitwarden_error;
use futures::{StreamExt, stream};
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::{
    hibp::{self, HIBP_DEFAULT_BASE_URL},
    password_strength,
    types::{
        CipherLoginDetails, CipherRiskOptions, CipherRiskResult, ExposedPasswordResult,
        PasswordReuseMap,
    },
};

/// Error type for cipher risk evaluation operations
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CipherRiskError {
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
}

/// Maximum number of concurrent requests when checking passwords.
const MAX_CONCURRENT_REQUESTS: usize = 100;

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
    pub fn password_reuse_map(&self, login_details: Vec<CipherLoginDetails>) -> PasswordReuseMap {
        PasswordReuseMap::new(login_details)
    }

    /// Convert a single login details to CipherRisk.
    ///
    /// For the cipher:
    /// 1. Calculates password strength (0-4) using zxcvbn with cipher-specific context
    /// 2. Optionally checks if the password has been exposed via Have I Been Pwned API
    /// 3. Counts how many times the password is reused in the provided `password_map`
    async fn to_cipher_risk(
        http_client: reqwest::Client,
        details: CipherLoginDetails,
        password_map: Option<Arc<PasswordReuseMap>>,
        check_exposed: bool,
        base_url: String,
    ) -> CipherRiskResult {
        if details.password.is_empty() {
            // Skip empty passwords, return default risk values
            return CipherRiskResult {
                id: details.id,
                password_strength: 0,
                exposed_result: ExposedPasswordResult::NotChecked,
                reuse_count: None,
            };
        }

        let password_strength = password_strength::calculate_password_strength(
            &details.password,
            details.username.as_deref(),
        );

        // Check exposure via HIBP API if enabled
        // Capture errors per-cipher instead of propagating them
        let exposed_result = if check_exposed {
            match hibp::check_password_exposed(&http_client, &details.password, &base_url).await {
                Ok(count) => ExposedPasswordResult::Found(count),
                Err(e) => ExposedPasswordResult::Error(e.to_string()),
            }
        } else {
            ExposedPasswordResult::NotChecked
        };

        // Check reuse from provided map
        let reuse_count = password_map
            .as_ref()
            .and_then(|m| m.map.get(&details.password).copied());

        CipherRiskResult {
            id: details.id,
            password_strength,
            exposed_result,
            reuse_count,
        }
    }

    /// Evaluate security risks for multiple login ciphers concurrently.
    ///
    /// For each cipher:
    /// 1. Calculates password strength (0-4) using zxcvbn with cipher-specific context
    /// 2. Optionally checks if the password has been exposed via Have I Been Pwned API
    /// 3. Counts how many times the password is reused in the provided `password_map`
    ///
    /// Returns a vector of `CipherRisk` results, one for each input cipher.
    ///
    /// ## HIBP Check Results (`exposed_result` field)
    ///
    /// The `exposed_result` field uses the `ExposedPasswordResult` enum with three possible states:
    /// - `NotChecked`: Password exposure check was not performed because:
    ///   - `check_exposed` option was `false`, or
    ///   - Password was empty
    /// - `Found(n)`: Successfully checked via HIBP API, password appears in `n` data breaches
    /// - `Error(msg)`: HIBP API request failed with error message `msg`
    ///
    /// # Errors
    ///
    /// This method only returns `Err` for internal logic failures. HIBP API errors are
    /// captured per-cipher in the `exposed_result` field as `ExposedPasswordResult::Error(msg)`.
    pub async fn compute_risk(
        &self,
        login_details: Vec<CipherLoginDetails>,
        options: CipherRiskOptions,
    ) -> Result<Vec<CipherRiskResult>, CipherRiskError> {
        // Wrap password_map in Arc to avoid cloning the HashMap for each future
        let password_map = options.password_map.map(Arc::new);
        let base_url = options
            .hibp_base_url
            .unwrap_or_else(|| HIBP_DEFAULT_BASE_URL.to_string());

        // Create futures that can run concurrently
        let futures = login_details.into_iter().map(|details| {
            Self::to_cipher_risk(
                self.client.internal.get_http_client().clone(),
                details,
                password_map.as_ref().map(Arc::clone),
                options.check_exposed,
                base_url.clone(),
            )
        });

        // Process up to MAX_CONCURRENT_REQUESTS futures concurrently
        // Individual HIBP errors are captured per-cipher, so we use collect() instead of
        // try_collect()
        let results: Vec<CipherRiskResult> = stream::iter(futures)
            .buffer_unordered(MAX_CONCURRENT_REQUESTS)
            .collect()
            .await;

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account;

    use super::*;

    #[tokio::test]
    async fn test_password_reuse_map() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let risk_client = CipherRiskClient {
            client: client.clone(),
        };

        let login_details = vec![
            CipherLoginDetails {
                id: Default::default(),
                password: "password123".to_string(),
                username: Some("user1".to_string()),
            },
            CipherLoginDetails {
                id: Default::default(),
                password: "password123".to_string(),
                username: Some("user2".to_string()),
            },
            CipherLoginDetails {
                id: Default::default(),
                password: "unique_password".to_string(),
                username: Some("user3".to_string()),
            },
        ];

        let password_map = risk_client.password_reuse_map(login_details);

        assert_eq!(password_map.map.get("password123"), Some(&2));
        assert_eq!(password_map.map.get("unique_password"), Some(&1));
    }

    #[tokio::test]
    async fn test_password_reuse_map_empty_passwords() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let risk_client = CipherRiskClient {
            client: client.clone(),
        };

        let login_details = vec![
            CipherLoginDetails {
                id: Default::default(),
                password: "".to_string(),
                username: Some("user1".to_string()),
            },
            CipherLoginDetails {
                id: Default::default(),
                password: "valid_password".to_string(),
                username: Some("user2".to_string()),
            },
        ];

        let password_map = risk_client.password_reuse_map(login_details);

        // Empty passwords should not be in the map
        assert!(!password_map.map.contains_key(""));
        assert_eq!(password_map.map.get("valid_password"), Some(&1));
    }

    #[tokio::test]
    async fn test_compute_risk_skips_empty_passwords() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let risk_client = CipherRiskClient { client };

        let login_details = vec![CipherLoginDetails {
            id: Default::default(),
            password: "".to_string(),
            username: Some("user1".to_string()),
        }];

        let options = CipherRiskOptions {
            password_map: None,
            check_exposed: true, // Enable HIBP checking
            hibp_base_url: None,
        };

        let result = risk_client.compute_risk(login_details, options).await;

        // Verify that empty passwords are skipped (no HIBP check performed)
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].password_strength, 0);
        assert_eq!(results[0].exposed_result, ExposedPasswordResult::NotChecked);
        assert_eq!(results[0].reuse_count, None);
    }

    #[tokio::test]
    async fn test_compute_risk_captures_network_errors_per_cipher() {
        // Test that network errors from HIBP API are captured per-cipher
        // instead of canceling the entire batch
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
            id: Default::default(),
            password: "password123".to_string(),
            username: Some("user1".to_string()),
        }];

        let options = CipherRiskOptions {
            password_map: None,
            check_exposed: true, // Enable HIBP checking
            hibp_base_url: Some(server.uri()),
        };

        let result = risk_client.compute_risk(login_details, options).await;

        // Verify operation succeeds but error is captured per-cipher
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 1);

        // The exposed_result should be Error(...)
        match &results[0].exposed_result {
            ExposedPasswordResult::Error(msg) => {
                assert!(!msg.is_empty(), "Error message should not be empty");
            }
            ExposedPasswordResult::Found(_) => {
                panic!("Expected Error variant, but got Found");
            }
            ExposedPasswordResult::NotChecked => {
                panic!("Expected Error variant, but got NotChecked");
            }
        }
    }

    #[tokio::test]
    async fn test_compute_risk_partial_failures() {
        // Test that when some HIBP checks succeed and others fail,
        // all results are returned with appropriate success/error states
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        let server = MockServer::start().await;

        // Hash prefix for "password1": E38AD (SHA1: E38AD214943DAAD1D64C102FAEC29DE4AFE9DA3D)
        // Hash prefix for "password2": 2AA60 (SHA1: 2AA60A8FF7FCD473D321E0146AFD9E26DF395147)

        // Mock success for password1's hash prefix - return the suffix for password1
        Mock::given(method("GET"))
            .and(path("/range/E38AD"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("214943DAAD1D64C102FAEC29DE4AFE9DA3D:5\r\n"),
            )
            .mount(&server)
            .await;

        // Mock failure for password2's hash prefix
        Mock::given(method("GET"))
            .and(path("/range/2AA60"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let risk_client = CipherRiskClient { client };

        let login_details = vec![
            CipherLoginDetails {
                id: Default::default(),
                password: "password1".to_string(),
                username: Some("user1".to_string()),
            },
            CipherLoginDetails {
                id: Default::default(),
                password: "password2".to_string(),
                username: Some("user2".to_string()),
            },
        ];

        let options = CipherRiskOptions {
            password_map: None,
            check_exposed: true,
            hibp_base_url: Some(server.uri()),
        };

        let result = risk_client.compute_risk(login_details, options).await;

        // Operation should succeed
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 2);

        // Count successes and failures
        let mut success_count = 0;
        let mut error_count = 0;

        for result in &results {
            match &result.exposed_result {
                ExposedPasswordResult::Found(_) => success_count += 1,
                ExposedPasswordResult::Error(_) => error_count += 1,
                ExposedPasswordResult::NotChecked => {
                    panic!("Expected Found or Error, but got NotChecked")
                }
            }
        }

        // We should have exactly one success and one failure
        assert_eq!(
            success_count, 1,
            "Expected 1 successful HIBP check, got {}",
            success_count
        );
        assert_eq!(
            error_count, 1,
            "Expected 1 failed HIBP check, got {}",
            error_count
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
                id: Default::default(),
                password: "weak".to_string(),
                username: Some("user1".to_string()),
            },
            CipherLoginDetails {
                id: Default::default(),
                password: "xK9#mP$2qL@7vN&4wR".to_string(),
                username: Some("user2".to_string()),
            },
        ];

        let password_map = risk_client.password_reuse_map(login_details.clone());

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
        assert_eq!(results[0].reuse_count, Some(1));
        assert_eq!(results[1].reuse_count, Some(1));

        // HIBP not checked
        assert_eq!(results[0].exposed_result, ExposedPasswordResult::NotChecked);
        assert_eq!(results[1].exposed_result, ExposedPasswordResult::NotChecked);
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
                id: Default::default(),
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

        // Verify all passwords were checked successfully
        for result in &results {
            match &result.exposed_result {
                ExposedPasswordResult::Found(_) => {
                    // Success - password was checked
                }
                ExposedPasswordResult::Error(err) => {
                    panic!("HIBP check should succeed, got error: {}", err);
                }
                ExposedPasswordResult::NotChecked => {
                    panic!("All passwords should be checked when check_exposed=true");
                }
            }
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
