//! Have I Been Pwned (HIBP) API client for password breach checking.
//!
//! This module implements k-anonymity based password checking against the HIBP API.

use super::CipherRiskError;

/// Default base URL for the Have I Been Pwned (HIBP) Pwned Passwords API.
pub(super) const HIBP_DEFAULT_BASE_URL: &str = "https://api.pwnedpasswords.com";

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
    response
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(hash_suffix, _)| hash_suffix.eq_ignore_ascii_case(target_suffix))
        .and_then(|(_, count_str)| count_str.trim().parse().ok())
        .unwrap_or(0)
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
pub(super) async fn check_password_exposed(
    http_client: &reqwest::Client,
    password: &str,
    hibp_base_url: &str,
) -> Result<u32, CipherRiskError> {
    let (prefix, suffix) = hash_password_for_hibp(password);

    // Query HIBP API with prefix only (k-anonymity)
    let url = format!("{}/range/{}", hibp_base_url, prefix);
    let response = http_client
        .get(&url)
        .send()
        .await
        .map_err(|e| e.without_url())?
        .error_for_status()
        .map_err(|e| e.without_url())?
        .text()
        .await
        .map_err(|e| e.without_url())?;

    Ok(parse_hibp_response(&response, &suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password_for_hibp() {
        // Test with a known password: "password"
        // SHA-1 hash of "password" is: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = hash_password_for_hibp("password");

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

        let count = parse_hibp_response(mock_response, target_suffix);

        assert_eq!(count, 6);
    }

    #[test]
    fn test_parse_hibp_response_not_found() {
        // Simulate HIBP API response without target hash
        let mock_response = "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n\
                            00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\r\n\
                            011053FD0102E94D6AE2F8B83D76FAF94F6:1\r\n";

        let target_suffix = "NOTFOUNDNOTFOUNDNOTFOUNDNOTFOUND";

        let count = parse_hibp_response(mock_response, target_suffix);

        assert_eq!(count, 0);
    }

    #[test]
    fn test_parse_hibp_response_case_insensitive() {
        // HIBP API returns uppercase hashes, but we should match case-insensitively
        let mock_response = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\r\n";

        // Test with lowercase suffix
        let target_suffix_lower = "1e4c9b93f3f0682250b6cf8331b7ee68fd8";

        let count = parse_hibp_response(mock_response, target_suffix_lower);

        assert_eq!(count, 12345);
    }

    #[test]
    fn test_parse_hibp_response_empty() {
        // Empty response
        let mock_response = "";

        let count = parse_hibp_response(mock_response, "ANYTHING");
        assert_eq!(count, 0);
    }

    #[test]
    fn test_parse_hibp_response_malformed_count() {
        // Response with invalid count (should return 0 on parse failure)
        let mock_response = "AAA111:not_a_number\r\n";

        let count = parse_hibp_response(mock_response, "AAA111");
        assert_eq!(count, 0);
    }

    // Wiremock tests for actual HIBP API integration
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

        let result =
            check_password_exposed(&reqwest::Client::new(), "password", &server.uri()).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CipherRiskError::Reqwest(_)));
    }
}
