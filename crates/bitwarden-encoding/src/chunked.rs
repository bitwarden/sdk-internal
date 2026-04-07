use data_encoding::Encoding;

/// Encodes data using the provided encoding, transparently chunking to work around
/// `data-encoding`'s `encode_len` length assertion (`len <= usize::MAX / 512`, ~8 MB on 32-bit
/// targets like wasm32). On 64-bit targets the limit is effectively infinite so all input fits in a
/// single chunk.
pub(crate) fn chunked_encode(encoding: &Encoding, data: &[u8]) -> String {
    chunked_encode_with_limit(encoding, data, usize::MAX / 512)
}

fn chunked_encode_with_limit(encoding: &Encoding, data: &[u8], max_safe: usize) -> String {
    // Round down to the nearest multiple of `encode_align` so intermediate chunks
    // produce clean output without spurious padding. Only the final chunk may produce padding.
    let align = encoding.encode_align();
    let max_chunk = max_safe - max_safe % align;

    // Base64 output is ~4/3 of input; slightly over-estimate to avoid reallocations.
    let mut output = String::with_capacity(data.len() / 3 * 4 + 4);
    for chunk in data.chunks(max_chunk) {
        encoding.encode_append(chunk, &mut output);
    }
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
        // 30 bytes of input, chunked at max_safe=6 → align=3, max_chunk=6
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
    fn chunk_boundary_not_aligned_to_three() {
        // max_safe=7 with align=3 → max_chunk=6 (rounds down), same as above
        // but verifies the alignment rounding logic.
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
