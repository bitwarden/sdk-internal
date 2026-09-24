use rand::Rng;

use super::KeeperCryptoError;

/// Generate `length` cryptographically secure random bytes.
pub(crate) fn get_random_bytes(length: usize) -> Vec<u8> {
    let mut buf = vec![0u8; length];
    bitwarden_random::rng().fill_bytes(&mut buf);
    buf
}

/// Encode bytes as unpadded URL-safe base64 (Keeper's `base64UrlEncode`).
pub(crate) fn base64_url_encode(data: &[u8]) -> String {
    data_encoding::BASE64URL_NOPAD.encode(data)
}

/// Decode unpadded URL-safe base64 (Keeper's `base64UrlDecode`).
///
/// Any trailing `=` padding is tolerated to match the lenient behaviour of the TypeScript original.
pub(crate) fn base64_url_decode(text: &str) -> Result<Vec<u8>, KeeperCryptoError> {
    let trimmed = text.trim_end_matches('=');
    data_encoding::BASE64URL_NOPAD
        .decode(trimmed.as_bytes())
        .map_err(|_| KeeperCryptoError::InvalidData)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_random_bytes_generates_correct_length() {
        assert_eq!(get_random_bytes(0).len(), 0);
        assert_eq!(get_random_bytes(1).len(), 1);
        assert_eq!(get_random_bytes(32).len(), 32);
        assert_eq!(get_random_bytes(256).len(), 256);
    }

    #[test]
    fn get_random_bytes_produces_different_values() {
        let bytes1 = get_random_bytes(32);
        let bytes2 = get_random_bytes(32);
        // Statistically extremely unlikely to generate identical random data
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn base64_url_encode_empty() {
        assert_eq!(base64_url_encode(&[]), "");
    }

    #[test]
    fn base64_url_encode_single_byte() {
        assert_eq!(base64_url_encode(&[0]), "AA");
        assert_eq!(base64_url_encode(&[255]), "_w");
    }

    #[test]
    fn base64_url_encode_uses_url_safe_alphabet() {
        // Standard base64 would use '+' and '/', URL-safe uses '-' and '_'
        let data = &[0xfb, 0xff, 0x00];
        let encoded = base64_url_encode(data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(encoded.contains('-') || encoded.contains('_') || encoded == "u_8A");
    }

    #[test]
    fn base64_url_encode_has_no_padding() {
        // Unpadded base64 should never contain '='
        let encoded = base64_url_encode(&[0u8; 10]);
        assert!(!encoded.contains('='));
    }

    #[test]
    fn base64_url_decode_empty() {
        assert_eq!(base64_url_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn base64_url_decode_single_byte() {
        assert_eq!(base64_url_decode("AA").unwrap(), vec![0]);
        assert_eq!(base64_url_decode("_w").unwrap(), vec![255]);
    }

    #[test]
    fn base64_url_decode_tolerates_padding() {
        // Should accept trailing '=' even though we generate unpadded
        assert_eq!(base64_url_decode("AA").unwrap(), vec![0]);
        assert_eq!(base64_url_decode("AA=").unwrap(), vec![0]);
        assert_eq!(base64_url_decode("AA==").unwrap(), vec![0]);
    }

    #[test]
    fn base64_url_decode_rejects_invalid_input() {
        assert!(base64_url_decode("!!!").is_err());
        assert!(base64_url_decode("@@@@").is_err());
        assert!(base64_url_decode("\x00\x01\x02").is_err());
    }

    #[test]
    fn base64_url_round_trip() {
        let original = b"Hello, Keeper!";
        let encoded = base64_url_encode(original);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn base64_url_round_trip_binary() {
        let original = [0xfb, 0xff, 0x00, 0x10, 0x3e, 0x7d];
        let encoded = base64_url_encode(&original);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded.as_slice(), &original);
    }

    #[test]
    fn base64_url_round_trip_empty() {
        let original: &[u8] = &[];
        let encoded = base64_url_encode(original);
        let decoded: Vec<u8> = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded.as_slice(), original);
    }

    #[test]
    fn base64_url_round_trip_various_lengths() {
        for length in [0, 1, 2, 3, 4, 5, 10, 31, 32, 33, 64, 255] {
            let original = get_random_bytes(length);
            let encoded = base64_url_encode(&original);
            let decoded = base64_url_decode(&encoded).unwrap();
            assert_eq!(decoded, original, "Round trip failed for length {}", length);
        }
    }

    #[test]
    fn base64_url_encode_known_vectors() {
        // Test against known base64url vectors (RFC 4648)
        assert_eq!(base64_url_encode(b"abc"), "YWJj");
        assert_eq!(base64_url_encode(b"abcd"), "YWJjZA");
        // The following contains standard base64 padding, but we use unpadded
        assert_eq!(base64_url_encode(b"ab"), "YWI");
    }

    #[test]
    fn base64_url_decode_known_vectors() {
        assert_eq!(base64_url_decode("YWJj").unwrap(), b"abc");
        assert_eq!(base64_url_decode("YWJjZA").unwrap(), b"abcd");
        assert_eq!(base64_url_decode("YWI").unwrap(), b"ab");
    }
}
