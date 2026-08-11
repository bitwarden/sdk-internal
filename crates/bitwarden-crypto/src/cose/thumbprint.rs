//! [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679) COSE Key Thumbprints.
//!
//! A COSE Key Thumbprint is a deterministic hash of a COSE_Key — the COSE analogue of the JWK
//! thumbprint ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)). It is computed by:
//!
//! 1. Collecting **only** the parameters required for that key type (e.g. for an OKP key `kty`,
//!    `crv`, and `x`), excluding `kid`, `key_ops`, and any private material.
//! 2. Encoding those parameters as a CBOR map using the deterministic encoding of [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1)
//!    (definite-length map, shortest-form integers, map keys sorted bytewise-lexicographically by
//!    their encoded bytes).
//! 3. Hashing the result. This implementation only supports the RFC 9679 default hash, SHA-256.
//!
//! Because the thumbprint is computed over public material for asymmetric keys, a private key and
//! its corresponding public key produce the same thumbprint. The same applies for signature key
//! pairs / their verification key.

use ciborium::{Value, value::Integer};
use sha2::{Digest, Sha256};

/// An [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679) COSE Key Thumbprint.
///
/// ```no_run
/// use bitwarden_crypto::{CoseKeyThumbprintExt, SignatureAlgorithm, SigningKey};
///
/// let key = SigningKey::make(SignatureAlgorithm::Ed25519);
/// let thumbprint = key.thumbprint().expect("Ed25519 keys are always COSE-representable");
/// println!("{}", thumbprint); // e.g. "SHA256:50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c"
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct CoseKeyThumbprint([u8; 32]);

impl CoseKeyThumbprint {
    /// The raw 32-byte SHA-256 digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constructs a thumbprint from a raw 32-byte SHA-256 digest.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        CoseKeyThumbprint(bytes)
    }

    /// The thumbprint as a lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for CoseKeyThumbprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SHA256:{}", self.to_hex())
    }
}

impl std::fmt::Debug for CoseKeyThumbprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CoseKeyThumbprint({})", self.to_hex())
    }
}

/// Computes the [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679) COSE Key Thumbprint of a key.
pub trait CoseKeyThumbprintExt {
    /// Returns the SHA-256 COSE Key Thumbprint of this key.
    fn thumbprint(&self) -> Result<CoseKeyThumbprint, crate::CryptoError>;
}

/// Builds the RFC 9679 thumbprint from a key type's required parameters.
///
/// `params` is the list of `(label, value)` pairs of the required parameters (order does not
/// matter; this function sorts them into the RFC 8949 §4.2.1 deterministic order). The pairs are
/// encoded as a canonical CBOR map and hashed with SHA-256.
pub(crate) fn thumbprint_from_required_params(mut params: Vec<(i64, Value)>) -> CoseKeyThumbprint {
    // RFC 8949 §4.2.1: map keys are sorted by the bytewise lexicographic order of their encoded
    // representation. Encoding each label to CBOR and comparing the bytes is exactly this rule.
    params.sort_by_key(|(label, _)| encoded_label(*label));

    let map = Value::Map(
        params
            .into_iter()
            .map(|(label, value)| (Value::Integer(Integer::from(label)), value))
            .collect(),
    );

    let mut buf = Vec::new();
    ciborium::into_writer(&map, &mut buf)
        .expect("CBOR serialization of a COSE key parameter map cannot fail");
    CoseKeyThumbprint(Sha256::digest(&buf).into())
}

/// Returns the CBOR encoding of an integer label, used as the sort key for canonical ordering.
fn encoded_label(label: i64) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(&Value::Integer(Integer::from(label)), &mut buf)
        .expect("CBOR serialization of an integer label cannot fail");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Example from RFC 9679 §6, an EC2 / P-256 key, given in CBOR extended diagnostic notation:
    ///
    /// ```text
    /// {
    ///   / kty set to EC2 = Elliptic Curve Keys /
    ///   1:2,
    ///   / crv set to P-256 /
    ///   -1:1,
    ///   / public key: x-coordinate /
    ///   -2:h'65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d',
    ///   / public key: y-coordinate /
    ///   -3:h'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c',
    ///   / kid is bstr, not used in COSE Key Thumbprint /
    ///   2:h'496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec'
    /// }
    /// ```
    ///
    /// EC2 is not a key type we otherwise support, but validating against it exercises the shared
    /// canonicalization + CBOR + SHA-256 pipeline against the RFC's own test vector. Note the
    /// `kid` above happens to equal the thumbprint (the RFC reuses it as a worked example of a
    /// `kid` set from a key's own thumbprint), but it is not itself hashed — like any other
    /// non-required parameter, it's excluded from the input.
    #[test]
    fn test_rfc9679_ec2_example() {
        let x = hex::decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d")
            .unwrap();
        let y = hex::decode("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c")
            .unwrap();
        let expected_thumbprint =
            "496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec";

        // Intentionally provide the params out of canonical order to exercise the sort.
        let params = vec![
            (-3i64, Value::Bytes(y)),
            (1i64, Value::Integer(Integer::from(2))),
            (-2i64, Value::Bytes(x)),
            (-1i64, Value::Integer(Integer::from(1))),
        ];

        let thumbprint = thumbprint_from_required_params(params);
        assert_eq!(thumbprint.to_hex(), expected_thumbprint);
    }

    #[test]
    fn test_accessors() {
        let thumbprint =
            thumbprint_from_required_params(vec![(1i64, Value::Integer(Integer::from(4)))]);
        assert_eq!(thumbprint.as_bytes().len(), 32);
        assert_eq!(thumbprint.to_hex().len(), 64);
    }
}
