use bitwarden_vault::{Totp, TotpAlgorithm};
use credential_exchange_format::{OTPHashAlgorithm, TotpCredential};

/// Convert CXF TotpCredential to Bitwarden's Totp struct
/// This ensures we use the exact same encoding and formatting as Bitwarden's core implementation
pub fn totp_credential_to_totp(cxf_totp: &TotpCredential) -> Totp {
    let algorithm = match cxf_totp.algorithm {
        OTPHashAlgorithm::Sha1 => TotpAlgorithm::Sha1,
        OTPHashAlgorithm::Sha256 => TotpAlgorithm::Sha256,
        OTPHashAlgorithm::Sha512 => TotpAlgorithm::Sha512,
        OTPHashAlgorithm::Unknown(ref algo) if algo == "steam" => TotpAlgorithm::Steam,
        OTPHashAlgorithm::Unknown(_) | _ => TotpAlgorithm::Sha1, /* Default to SHA1 for unknown
                                                                  * algorithms */
    };

    let secret_bytes: Vec<u8> = cxf_totp.secret.clone().into();

    Totp {
        account: cxf_totp.username.clone(),
        algorithm,
        digits: cxf_totp.digits as u32,
        issuer: cxf_totp.issuer.clone(),
        period: cxf_totp.period as u32,
        secret: secret_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cxf_sample_totp_mapping() {
        use std::fs;

        use crate::cxf::import::parse_cxf_spec;

        // Load the actual CXF example file
        let cxf_data = fs::read_to_string("resources/cxf_example.json")
            .expect("Should be able to read cxf_example.json");

        let items = parse_cxf_spec(cxf_data).expect("Should be able to parse CXF");

        // Find the item with TOTP - should be the "GitHub Login" item
        let totp_item = items
            .iter()
            .find(|item| item.name == "GitHub Login")
            .expect("Should find GitHub Login item");

        // Verify it's a Login type with TOTP
        match &totp_item.r#type {
            crate::CipherType::Login(login) => {
                // Verify the TOTP field is properly mapped
                assert!(login.totp.is_some());
                let totp_uri = login.totp.as_ref().unwrap();

                // Verify it's a proper otpauth URI
                assert!(totp_uri.starts_with("otpauth://totp/"));

                // Verify it contains the expected components from the CXF sample:
                // - secret: "JBSWY3DPEHPK3PXP"
                // - issuer: "Google"
                // - algorithm: "sha256" (non-default, should appear as SHA256)
                // - username: "jane.smith@example.com" (in the URI label)
                // - period: 30 (default, so should NOT appear in URI)
                // - digits: 6 (default, so should NOT appear in URI)
                assert!(totp_uri.contains("secret=JBSWY3DPEHPK3PXP"));
                assert!(totp_uri.contains("issuer=Google"));
                assert!(totp_uri.contains("algorithm=SHA256"));
                assert!(totp_uri.contains("Google:jane%2Esmith%40example%2Ecom"));

                // Should NOT contain default values
                assert!(!totp_uri.contains("period=30"));
                assert!(!totp_uri.contains("digits=6"));

                // Verify the Login structure is complete
                assert!(login.username.is_some()); // From basic auth credential
                assert!(login.password.is_some()); // From basic auth credential
                assert!(!login.login_uris.is_empty()); // From item scope
                assert!(login.totp.is_some()); // From TOTP credential

                // Expected URI format using official Bitwarden TOTP implementation:
                // otpauth://totp/Google:jane%2Esmith%40example%2Ecom?secret=JBSWY3DPEHPK3PXP&
                // issuer=Google&algorithm=SHA256
            }
            _ => panic!("GitHub Login item should be a Login type"),
        }
    }

    #[test]
    fn test_totp_credential_to_totp_basic() {
        let totp = TotpCredential {
            secret: "Hello World!".as_bytes().to_vec().into(),
            period: 30,
            digits: 6,
            username: Some("test@example.com".to_string()),
            algorithm: OTPHashAlgorithm::Sha1,
            issuer: Some("Example".to_string()),
        };

        let bitwarden_totp = totp_credential_to_totp(&totp);
        let otpauth = bitwarden_totp.to_string();

        assert!(otpauth.starts_with("otpauth://totp/Example:test%40example%2Ecom?secret="));
        assert!(otpauth.contains("&issuer=Example"));
        // Default period (30) and digits (6) and algorithm (SHA1) should not be included
        assert!(!otpauth.contains("&period=30"));
        assert!(!otpauth.contains("&digits=6"));
        assert!(!otpauth.contains("&algorithm=SHA1"));
    }

    #[test]
    fn test_totp_credential_to_totp_custom_parameters() {
        let totp = TotpCredential {
            secret: "Hello World!".as_bytes().to_vec().into(),
            period: 60,
            digits: 8,
            username: Some("user".to_string()),
            algorithm: OTPHashAlgorithm::Sha256,
            issuer: Some("Custom Issuer".to_string()),
        };

        let bitwarden_totp = totp_credential_to_totp(&totp);
        let otpauth = bitwarden_totp.to_string();

        assert!(otpauth.contains("Custom%20Issuer:user"));
        assert!(otpauth.contains("&issuer=Custom%20Issuer"));
        assert!(otpauth.contains("&period=60"));
        assert!(otpauth.contains("&digits=8"));
        assert!(otpauth.contains("&algorithm=SHA256"));
    }

    #[test]
    fn test_totp_credential_to_totp_sha512() {
        let totp = TotpCredential {
            secret: "secret123".as_bytes().to_vec().into(),
            period: 30,
            digits: 6,
            username: Some("user".to_string()),
            algorithm: OTPHashAlgorithm::Sha512,
            issuer: None,
        };

        let bitwarden_totp = totp_credential_to_totp(&totp);
        let otpauth = bitwarden_totp.to_string();

        assert!(otpauth.starts_with("otpauth://totp/user?secret="));
        assert!(otpauth.contains("&algorithm=SHA512"));
        assert!(!otpauth.contains("&issuer="));
    }

    #[test]
    fn test_totp_credential_to_totp_steam() {
        let totp = TotpCredential {
            secret: "secret123".as_bytes().to_vec().into(),
            period: 30,
            digits: 5,
            username: Some("steamuser".to_string()),
            algorithm: OTPHashAlgorithm::Unknown("steam".to_string()),
            issuer: Some("Steam".to_string()),
        };

        let bitwarden_totp = totp_credential_to_totp(&totp);
        let otpauth = bitwarden_totp.to_string();

        // Steam uses special format
        assert!(otpauth.starts_with("steam://"));
        assert!(!otpauth.contains("otpauth://"));
    }

    #[test]
    fn test_totp_credential_to_totp_no_username_no_issuer() {
        let totp = TotpCredential {
            secret: "test".as_bytes().to_vec().into(),
            period: 30,
            digits: 6,
            username: None,
            algorithm: OTPHashAlgorithm::Sha1,
            issuer: None,
        };

        let bitwarden_totp = totp_credential_to_totp(&totp);
        let otpauth = bitwarden_totp.to_string();

        // Should have empty label but still be valid
        assert!(otpauth.starts_with("otpauth://totp"));
        assert!(otpauth.contains("secret="));
    }

    #[test]
    fn test_totp_credential_to_totp_colon_stripping() {
        let totp = TotpCredential {
            secret: "test".as_bytes().to_vec().into(),
            period: 30,
            digits: 6,
            username: Some("user:with:colons".to_string()),
            algorithm: OTPHashAlgorithm::Sha1,
            issuer: Some("issuer:with:colons".to_string()),
        };

        let bitwarden_totp = totp_credential_to_totp(&totp);
        let otpauth = bitwarden_totp.to_string();

        // Check what the official implementation does with colons
        assert!(otpauth.starts_with("otpauth://totp/"));
        assert!(otpauth.contains("secret="));
        assert!(otpauth.contains("issuer="));

        // Verify colons are stripped from labels but preserved in issuer parameter
        assert!(otpauth.contains("issuerwithcolons:userwithcolons"));
        assert!(otpauth.contains("issuer=issuerwithcolons"));
    }

    #[test]
    fn test_build_otpauth_uri() {
        let totp_credential = TotpCredential {
            secret: "Hello World!".as_bytes().to_vec().into(),
            period: 30,
            digits: 6,
            username: Some("test@bitwarden.com".to_string()),
            algorithm: OTPHashAlgorithm::Sha1,
            issuer: Some("Bitwarden".to_string()),
        };

        // Convert to Bitwarden's Totp struct and use its Display implementation
        let bitwarden_totp = totp_credential_to_totp(&totp_credential);
        let uri = bitwarden_totp.to_string();

        // Verify it's a proper otpauth URI with the expected components
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("Bitwarden"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("issuer=Bitwarden"));

        // Should not contain default values (period=30, digits=6, algorithm=SHA1)
        assert!(!uri.contains("period=30"));
        assert!(!uri.contains("digits=6"));
        assert!(!uri.contains("algorithm=SHA1"));
    }
}
