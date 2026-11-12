use cshake::{
    CShake256,
    digest::{ExtendableOutput, Update, XofReader},
};

/// Function name `N` fixed by NIST SP 800-185 §5.
const FUNCTION_NAME: &[u8] = b"TupleHash";

/// TupleHash256 per NIST SP 800-185 §5.3.
pub(crate) fn tuple_hash256(items: &[&[u8]], customization: &[u8], out: &mut [u8]) {
    let mut xof = CShake256::new_with_function_name(FUNCTION_NAME, customization);

    for item in items {
        // encode_string(item) = left_encode(bit length) || item
        xof.update(&left_encode(bit_len(item.len())));
        xof.update(item);
    }
    xof.update(&right_encode(bit_len(out.len())));

    xof.finalize_xof().read(out);
}

fn bit_len(byte_len: usize) -> u64 {
    (byte_len as u64)
        .checked_mul(8)
        .expect("length in bits fits in u64")
}

/// `left_encode(x)`: byte count, then big-endian bytes of `x` (at least one).
fn left_encode(x: u64) -> Vec<u8> {
    let bytes = minimal_be(x);
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(bytes.len() as u8);
    out.extend_from_slice(&bytes);
    out
}

/// `right_encode(x)`: big-endian bytes of `x` (at least one), then byte count.
fn right_encode(x: u64) -> Vec<u8> {
    let mut out = minimal_be(x);
    out.push(out.len() as u8);
    out
}

fn minimal_be(x: u64) -> Vec<u8> {
    let be = x.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len() - 1);
    be[first..].to_vec()
}
