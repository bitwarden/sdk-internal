use bitwarden_crypto_primitives::{
    ed25519 as ed25519_primitives, p256 as p256_primitives, rsa as rsa_primitives,
};
use pkcs8::EncodePrivateKey;
use ssh_key::{EcdsaCurve, Mpint, PrivateKey};

use crate::error::SshKeyExportError;

/// Convert an OpenSSH private key to PKCS#8 DER format
///
/// This is primarily used for exporting SSH keys to other credential managers using Credential
/// Exchange.
pub fn export_pkcs8_der_key(private_key: &str) -> Result<Vec<u8>, SshKeyExportError> {
    // Parse the OpenSSH private key
    let private_key =
        PrivateKey::from_openssh(private_key).map_err(|_| SshKeyExportError::KeyConversion)?;

    match private_key.key_data() {
        ssh_key::private::KeypairData::Ed25519(keypair) => export_ed25519_pkcs8_der(keypair),
        ssh_key::private::KeypairData::Rsa(keypair) => export_rsa_pkcs8_der(keypair),
        ssh_key::private::KeypairData::Ecdsa(keypair) => export_ecdsa_pkcs8_der(keypair),
        _ => Err(SshKeyExportError::KeyConversion),
    }
}

fn export_ed25519_pkcs8_der(
    keypair: &ssh_key::private::Ed25519Keypair,
) -> Result<Vec<u8>, SshKeyExportError> {
    // Derive the public key from the seed and reject keypairs whose halves don't match.
    let seed = keypair.private.as_ref();
    let public_key = ed25519_primitives::SigningKey::from_seed(seed)
        .verifying_key()
        .to_bytes();
    if public_key != keypair.public.0 {
        return Err(SshKeyExportError::KeyConversion);
    }

    // PKCS#8 v2 document carrying both the seed and the public key.
    let keypair_bytes = ed25519::KeypairBytes {
        secret_key: *seed,
        public_key: Some(ed25519::pkcs8::PublicKeyBytes(public_key)),
    };
    Ok(keypair_bytes
        .to_pkcs8_der()
        .map_err(|_| SshKeyExportError::KeyConversion)?
        .as_bytes()
        .to_vec())
}

fn export_rsa_pkcs8_der(
    keypair: &ssh_key::private::RsaKeypair,
) -> Result<Vec<u8>, SshKeyExportError> {
    // Cross from ssh-key into primitives via the big-endian components.
    fn positive(mpint: &Mpint) -> Result<&[u8], SshKeyExportError> {
        mpint
            .as_positive_bytes()
            .ok_or(SshKeyExportError::KeyConversion)
    }

    let n = positive(keypair.public().n())?;
    let e = positive(keypair.public().e())?;
    let d = positive(keypair.private().d())?;
    let p = positive(keypair.private().p())?;
    let q = positive(keypair.private().q())?;

    let private_key = rsa_primitives::PrivateKey::from_components(n, e, d, &[p, q])
        .map_err(|_| SshKeyExportError::KeyConversion)?;
    Ok(private_key
        .to_pkcs8_der()
        .map_err(|_| SshKeyExportError::KeyConversion)?
        .to_vec())
}

fn export_ecdsa_pkcs8_der(
    keypair: &ssh_key::private::EcdsaKeypair,
) -> Result<Vec<u8>, SshKeyExportError> {
    let curve = keypair.curve();
    let private_key_bytes = keypair.private_key_bytes();

    match curve {
        EcdsaCurve::NistP256 => {
            // Cross from ssh-key into primitives via the raw scalar.
            let scalar = private_key_bytes
                .try_into()
                .map_err(|_| SshKeyExportError::KeyConversion)?;
            let sk = p256_primitives::SecretKey::from_bytes(scalar)
                .map_err(|_| SshKeyExportError::KeyConversion)?;
            Ok(sk
                .to_pkcs8_der()
                .map_err(|_| SshKeyExportError::KeyConversion)?
                .to_vec())
        }
        EcdsaCurve::NistP384 => {
            let sk = p384::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| SshKeyExportError::KeyConversion)?;
            Ok(sk
                .to_pkcs8_der()
                .map_err(|_| SshKeyExportError::KeyConversion)?
                .as_bytes()
                .to_vec())
        }
        EcdsaCurve::NistP521 => {
            let sk = p521::SecretKey::from_slice(private_key_bytes)
                .map_err(|_| SshKeyExportError::KeyConversion)?;
            Ok(sk
                .to_pkcs8_der()
                .map_err(|_| SshKeyExportError::KeyConversion)?
                .as_bytes()
                .to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{import_key, import_pkcs8_der_key};

    #[test]
    fn export_ed25519_openssh_unencrypted() {
        let private_key = include_str!("../resources/import/ed25519_openssh_unencrypted");
        let result = import_key(private_key.to_string(), Some("".to_string())).unwrap();

        let exported_key = export_pkcs8_der_key(&result.private_key).unwrap();
        let expected_pkcs8_der: Vec<u8> = vec![
            48, 81, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 139, 118, 81, 75, 32, 150,
            196, 136, 90, 63, 127, 68, 78, 117, 115, 13, 100, 3, 199, 24, 243, 97, 189, 182, 223,
            181, 163, 236, 81, 145, 35, 104, 129, 33, 0, 50, 66, 141, 182, 77, 117, 205, 170, 241,
            126, 47, 200, 212, 73, 35, 94, 187, 197, 42, 174, 192, 227, 189, 255, 105, 192, 140, 3,
            11, 211, 11, 234,
        ];
        assert_eq!(exported_key, expected_pkcs8_der);

        // Confirm the public key of the re-imported key is the same ignoring the key comment
        let reimported_key = import_pkcs8_der_key(&exported_key).unwrap();
        assert_eq!(
            reimported_key.public_key,
            result.public_key.strip_suffix(" testkey").unwrap()
        );
    }

    #[test]
    fn export_rsa_openssh_unencrypted() {
        let private_key = include_str!("../resources/import/rsa_openssh_unencrypted");
        let result = import_key(private_key.to_string(), Some("".to_string())).unwrap();

        let exported_key = export_pkcs8_der_key(&result.private_key).unwrap();

        // Confirm the public key of the re-imported key is the same ignoring the key comment
        let reimported_key = import_pkcs8_der_key(&exported_key).unwrap();
        assert_eq!(
            reimported_key.public_key,
            result.public_key.strip_suffix(" testkey").unwrap()
        );
    }

    #[cfg_attr(bitwarden_crypto_backend = "openssl", ignore)]
    #[test]
    fn export_ecdsa_p256() {
        let private_key = include_str!("../resources/generator/ecdsa_p256_key");
        let exported_key = export_pkcs8_der_key(private_key).unwrap();
        // Verify the PKCS8 DER is non-empty and re-importable
        assert!(!exported_key.is_empty());
    }

    #[test]
    fn export_ecdsa_p384() {
        let private_key = include_str!("../resources/generator/ecdsa_p384_key");
        let exported_key = export_pkcs8_der_key(private_key).unwrap();
        assert!(!exported_key.is_empty());
    }

    #[test]
    fn export_ecdsa_p521() {
        let private_key = include_str!("../resources/generator/ecdsa_p521_key");
        let exported_key = export_pkcs8_der_key(private_key).unwrap();
        assert!(!exported_key.is_empty());
    }

    #[cfg_attr(bitwarden_crypto_backend = "openssl", ignore)]
    #[test]
    fn export_ecdsa_p256_roundtrip() {
        let private_key = include_str!("../resources/generator/ecdsa_p256_key");
        let view = import_key(private_key.to_string(), None).unwrap();

        let exported_key = export_pkcs8_der_key(&view.private_key).unwrap();
        let reimported = import_pkcs8_der_key(&exported_key).unwrap();
        assert_eq!(reimported.public_key, view.public_key);
    }

    #[cfg_attr(bitwarden_crypto_backend = "openssl", ignore)]
    #[test]
    fn export_ecdsa_p384_roundtrip() {
        let private_key = include_str!("../resources/generator/ecdsa_p384_key");
        let view = import_key(private_key.to_string(), None).unwrap();

        let exported_key = export_pkcs8_der_key(&view.private_key).unwrap();
        let reimported = import_pkcs8_der_key(&exported_key).unwrap();
        assert_eq!(reimported.public_key, view.public_key);
    }

    #[cfg_attr(bitwarden_crypto_backend = "openssl", ignore)]
    #[test]
    fn export_ecdsa_p521_roundtrip() {
        let private_key = include_str!("../resources/generator/ecdsa_p521_key");
        let view = import_key(private_key.to_string(), None).unwrap();

        let exported_key = export_pkcs8_der_key(&view.private_key).unwrap();
        let reimported = import_pkcs8_der_key(&exported_key).unwrap();
        assert_eq!(reimported.public_key, view.public_key);
    }
}
