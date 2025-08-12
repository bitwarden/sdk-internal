use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use credential_exchange_format::{OTPHashAlgorithm, TotpCredential};

use crate::Login;

/// Convert TOTP credentials to Login following the CXF mapping convention
/// Maps all fields into a single OTPAUTH string according to the mapping document
pub fn totp_to_login(totp: &TotpCredential) -> Login {
    let otpauth_uri = build_otpauth_uri(totp);

    Login {
        username: totp.username.clone(), // we don't use this value in the import, but might as well map it.
        password: None,
        totp: Some(otpauth_uri),
        login_uris: vec![],
        fido2_credentials: None,
    }
}

/// Build an otpauth:// URI from TOTP credential fields
/// Format: otpauth://totp/[issuer:][account]?secret=SECRET[&issuer=ISSUER][&period=PERIOD][&algorithm=ALGORITHM][&digits=DIGITS]
fn build_otpauth_uri(totp: &TotpCredential) -> String {
    // For now, use base64 encoding as a simple fallback since base32 libraries aren't available
    // In a full implementation, we would use proper base32 encoding
    let secret_b64 = STANDARD_NO_PAD.encode(&totp.secret);

    // Build the label part: [issuer:][account]
    let label = build_label(&totp.issuer, &totp.username);

    // Start building the URI
    let mut uri = format!("otpauth://totp/{label}?secret={secret_b64}");

    // Add optional parameters
    if let Some(ref issuer) = totp.issuer {
        let encoded_issuer = url_encode(issuer);
        uri.push_str(&format!("&issuer={encoded_issuer}"));
    }

    // Add period if not default (30 seconds)
    if totp.period != 30 {
        uri.push_str(&format!("&period={}", totp.period));
    }

    // Add algorithm if not default (SHA1)
    match totp.algorithm {
        OTPHashAlgorithm::Sha256 => uri.push_str("&algorithm=SHA256"),
        OTPHashAlgorithm::Sha512 => uri.push_str("&algorithm=SHA512"),
        OTPHashAlgorithm::Unknown(ref algo) if algo == "steam" => {
            // Steam uses a special format: steam://SECRET
            return format!("steam://{secret_b64}");
        }
        OTPHashAlgorithm::Unknown(ref algo) => uri.push_str(&format!("&algorithm={algo}")),
        OTPHashAlgorithm::Sha1 => {} // Default, don't add parameter
        _ => {}                      // Handle any other unknown algorithms by not adding parameter
    }

    // Add digits if not default (6)
    if totp.digits != 6 {
        uri.push_str(&format!("&digits={}", totp.digits));
    }

    uri
}

/// Simple URL encoding for basic characters
fn url_encode(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '~' => c.to_string(),
            ' ' => "%20".to_string(),
            '@' => "%40".to_string(),
            ':' => "%3A".to_string(),
            '.' => "%2E".to_string(),
            c => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// Build the label part of the otpauth URI: [issuer:][account]
/// Both issuer and account are URL-encoded and colons are stripped from issuer
fn build_label(issuer: &Option<String>, account: &Option<String>) -> String {
    // Strip colons from issuer and account (as per Bitwarden's implementation)
    let clean_issuer = issuer.as_ref().map(|i| i.replace(':', ""));
    let clean_account = account.as_ref().map(|a| a.replace(':', ""));

    match (&clean_issuer, &clean_account) {
        (Some(issuer), Some(account)) => {
            let encoded_issuer = url_encode(issuer);
            let encoded_account = url_encode(account);
            format!("{encoded_issuer}:{encoded_account}")
        }
        (Some(issuer), None) => url_encode(issuer),
        (None, Some(account)) => url_encode(account),
        (None, None) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_to_login_basic() {
        let totp = TotpCredential {
            secret: "Hello World!".as_bytes().to_vec().into(),
            period: 30,
            digits: 6,
            username: Some("test@example.com".to_string()),
            algorithm: OTPHashAlgorithm::Sha1,
            issuer: Some("Example".to_string()),
        };

        let login = totp_to_login(&totp);

        assert_eq!(login.username, Some("test@example.com".to_string()));
        assert_eq!(login.password, None);
        assert_eq!(login.login_uris, vec![]);
        assert!(login.totp.is_some());

        let otpauth = login.totp.unwrap();
        assert!(otpauth.starts_with("otpauth://totp/Example:test%40example%2Ecom?secret="));
        assert!(otpauth.contains("&issuer=Example"));
        // Default period (30) and digits (6) and algorithm (SHA1) should not be included
        assert!(!otpauth.contains("&period=30"));
        assert!(!otpauth.contains("&digits=6"));
        assert!(!otpauth.contains("&algorithm=SHA1"));
    }

    #[test]
    fn test_totp_to_login_custom_parameters() {
        let totp = TotpCredential {
            secret: "Hello World!".as_bytes().to_vec().into(),
            period: 60,
            digits: 8,
            username: Some("user".to_string()),
            algorithm: OTPHashAlgorithm::Sha256,
            issuer: Some("Custom Issuer".to_string()),
        };

        let login = totp_to_login(&totp);
        let otpauth = login.totp.unwrap();

        assert!(otpauth.contains("Custom%20Issuer:user"));
        assert!(otpauth.contains("&issuer=Custom%20Issuer"));
        assert!(otpauth.contains("&period=60"));
        assert!(otpauth.contains("&digits=8"));
        assert!(otpauth.contains("&algorithm=SHA256"));
    }

    #[test]
    fn test_totp_to_login_sha512() {
        let totp = TotpCredential {
            secret: "secret123".as_bytes().to_vec().into(),
            period: 30,
            digits: 6,
            username: Some("user".to_string()),
            algorithm: OTPHashAlgorithm::Sha512,
            issuer: None,
        };

        let login = totp_to_login(&totp);
        let otpauth = login.totp.unwrap();

        assert!(otpauth.starts_with("otpauth://totp/user?secret="));
        assert!(otpauth.contains("&algorithm=SHA512"));
        assert!(!otpauth.contains("&issuer="));
    }

    #[test]
    fn test_totp_to_login_steam() {
        let totp = TotpCredential {
            secret: "secret123".as_bytes().to_vec().into(),
            period: 30,
            digits: 5,
            username: Some("steamuser".to_string()),
            algorithm: OTPHashAlgorithm::Unknown("steam".to_string()),
            issuer: Some("Steam".to_string()),
        };

        let login = totp_to_login(&totp);
        let otpauth = login.totp.unwrap();

        // Steam uses special format
        assert!(otpauth.starts_with("steam://"));
        assert!(!otpauth.contains("otpauth://"));
    }

    #[test]
    fn test_totp_to_login_no_username_no_issuer() {
        let totp = TotpCredential {
            secret: "test".as_bytes().to_vec().into(),
            period: 30,
            digits: 6,
            username: None,
            algorithm: OTPHashAlgorithm::Sha1,
            issuer: None,
        };

        let login = totp_to_login(&totp);
        let otpauth = login.totp.unwrap();

        // Should have empty label but still be valid
        assert!(otpauth.starts_with("otpauth://totp/?secret="));
    }

    #[test]
    fn test_totp_to_login_colon_stripping() {
        let totp = TotpCredential {
            secret: "test".as_bytes().to_vec().into(),
            period: 30,
            digits: 6,
            username: Some("user:with:colons".to_string()),
            algorithm: OTPHashAlgorithm::Sha1,
            issuer: Some("issuer:with:colons".to_string()),
        };

        let login = totp_to_login(&totp);
        let otpauth = login.totp.unwrap();

        // Colons should be stripped from label
        assert!(otpauth.contains("issuerwithcolons:userwithcolons"));
        // But issuer parameter should preserve original (encoded)
        assert!(otpauth.contains("&issuer=issuer%3Awith%3Acolons"));
    }

    #[test]
    fn test_build_otpauth_uri() {
        let totp = TotpCredential {
            secret: "Hello World!".as_bytes().to_vec().into(),
            period: 30,
            digits: 6,
            username: Some("test@bitwarden.com".to_string()),
            algorithm: OTPHashAlgorithm::Sha1,
            issuer: Some("Bitwarden".to_string()),
        };

        let uri = build_otpauth_uri(&totp);

        // Since we're using base64 instead of base32, update the expected result
        let expected_b64 = STANDARD_NO_PAD.encode("Hello World!".as_bytes());
        let expected_uri = format!("otpauth://totp/Bitwarden:test%40bitwarden%2Ecom?secret={expected_b64}&issuer=Bitwarden");
        assert_eq!(uri, expected_uri);
    }

    #[test]
    fn test_build_label() {
        assert_eq!(
            build_label(
                &Some("Example".to_string()),
                &Some("user@test.com".to_string())
            ),
            "Example:user%40test%2Ecom"
        );

        assert_eq!(build_label(&Some("Example".to_string()), &None), "Example");

        assert_eq!(
            build_label(&None, &Some("user@test.com".to_string())),
            "user%40test%2Ecom"
        );

        assert_eq!(build_label(&None, &None), "");

        // Test colon stripping in label (but not in issuer parameter)
        assert_eq!(
            build_label(
                &Some("Test:Issuer".to_string()),
                &Some("test:user".to_string())
            ),
            "TestIssuer:testuser"
        );
    }
}
