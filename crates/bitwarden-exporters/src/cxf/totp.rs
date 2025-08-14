use bitwarden_vault::{Totp, TotpAlgorithm};
use credential_exchange_format::{OTPHashAlgorithm, TotpCredential};

/// Convert CXF TotpCredential to Bitwarden's Totp struct
/// This ensures we use the exact same encoding and formatting as Bitwarden's core implementation
pub(super) fn totp_credential_to_totp(cxf_totp: &TotpCredential) -> Totp {
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
}
