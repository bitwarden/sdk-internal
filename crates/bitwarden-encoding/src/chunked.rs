use data_encoding::Encoding;

/// Encodes data using the provided encoding, transparently chunking to work around
/// `data-encoding`'s `encode_len` length assertion (`len <= usize::MAX / 512`, ~8 MB on 32-bit
/// targets like wasm32). On 64-bit targets the limit is effectively infinite so all input fits in a
/// single chunk.
pub(crate) fn chunked_encode(encoding: &Encoding, data: &[u8]) -> String {
    chunked_encode_with_limit(encoding, data, usize::MAX / 512)
}

fn chunked_encode_with_limit(encoding: &Encoding, data: &[u8], max_safe: usize) -> String {
    // Base64 output is ~4/3 of input; slightly over-estimate to avoid reallocations.
    let mut output = String::with_capacity(data.len() / 3 * 4 + 4);

    let mut enc = encoding.new_encoder(&mut output);
    for chunk in data.chunks(max_safe) {
        enc.append(chunk);
    }
    enc.finalize();
    output
}

#[cfg(test)]
mod tests {
    use data_encoding::{BASE64, BASE64URL_NOPAD};

    use super::*;

    #[test]
    fn single_chunk_matches_direct_encode() {
        let data = b"Hello, World!";
        assert_eq!(chunked_encode(&BASE64, data), BASE64.encode(data));
        assert_eq!(
            chunked_encode(&BASE64URL_NOPAD, data),
            BASE64URL_NOPAD.encode(data)
        );
    }

    #[test]
    fn multi_chunk_matches_direct_encode_base64() {
        // 30 bytes of input, chunked at max_safe=6
        // This forces 5 separate chunks.
        let data: Vec<u8> = (0..30).collect();
        let expected = BASE64.encode(&data);
        let result = chunked_encode_with_limit(&BASE64, &data, 6);
        assert_eq!(result, expected);
    }

    #[test]
    fn multi_chunk_matches_direct_encode_base64url() {
        let data: Vec<u8> = (0..30).collect();
        let expected = BASE64URL_NOPAD.encode(&data);
        let result = chunked_encode_with_limit(&BASE64URL_NOPAD, &data, 6);
        assert_eq!(result, expected);
    }

    #[test]
    fn unaligned_chunk_boundary() {
        // max_safe=7 is not a multiple of 3 (base64 input group size).
        // The streaming encoder handles this correctly without manual alignment.
        let data: Vec<u8> = (0..30).collect();
        let expected = BASE64.encode(&data);
        let result = chunked_encode_with_limit(&BASE64, &data, 7);
        assert_eq!(result, expected);
    }

    #[test]
    fn input_exactly_one_chunk() {
        let data: Vec<u8> = (0..6).collect();
        let expected = BASE64.encode(&data);
        let result = chunked_encode_with_limit(&BASE64, &data, 6);
        assert_eq!(result, expected);
    }

    #[test]
    fn input_one_byte_over_chunk() {
        let data: Vec<u8> = (0..7).collect();
        let expected = BASE64.encode(&data);
        let result = chunked_encode_with_limit(&BASE64, &data, 6);
        assert_eq!(result, expected);
    }

    #[test]
    fn empty_input() {
        assert_eq!(chunked_encode_with_limit(&BASE64, &[], 6), "");
        assert_eq!(chunked_encode_with_limit(&BASE64URL_NOPAD, &[], 6), "");
    }
}
