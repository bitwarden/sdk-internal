//! XAES-256-GCM per C2SP: derives a per-nonce AES-256 key from the first 12 nonce bytes with
//! AES-256-ECB and a CMAC subkey, then runs AES-256-GCM with the last 12 nonce bytes.
//!
//! ```text
//!   L  = AES-256_K(0^128)
//!   K1 = L << 1, XOR 0x87 into the last byte if the MSB of L was set
//!   Kx = AES-256_K(K1 XOR [0x00, 0x01, 'X', 0x00, N[..12]])
//!     || AES-256_K(K1 XOR [0x00, 0x02, 'X', 0x00, N[..12]])
//!   XAES-256-GCM(K, N, P, A) = AES-256-GCM(Kx, N[12..], P, A)
//! ```

use ::openssl::{cipher::Cipher, cipher_ctx::CipherCtx};
use zeroize::Zeroizing;

use super::aes_gcm;
use crate::{
    Error,
    xaes_256_gcm::{KEY_LEN, NONCE_LEN},
};

/// AES block length in bytes.
const BLOCK_LEN: usize = 16;
/// Nonce bytes that feed the key derivation; the rest is the GCM nonce.
const DERIVATION_NONCE_LEN: usize = 12;
/// CMAC subkey reduction constant for a 128-bit block (NIST SP 800-38B §5.3).
const RB: u8 = 0x87;
/// Per-half derivation prefixes: counter, label "X", separator.
const PREFIX_1: [u8; 4] = [0x00, 0x01, b'X', 0x00];
const PREFIX_2: [u8; 4] = [0x00, 0x02, b'X', 0x00];

pub(crate) fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    let (derived, gcm_nonce) = derive(key, nonce);
    aes_gcm::encrypt(&derived, &gcm_nonce, aad, plaintext)
}

pub(crate) fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let (derived, gcm_nonce) = derive(key, nonce);
    aes_gcm::decrypt(&derived, &gcm_nonce, aad, ciphertext)
}

/// Returns the derived key and the 12-byte GCM nonce.
fn derive(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> (Zeroizing<[u8; KEY_LEN]>, [u8; crate::aes_gcm::NONCE_LEN]) {
    const INFALLIBLE: &str = "AES-ECB of fixed-size in-memory blocks does not fail";

    let mut ctx = CipherCtx::new().expect(INFALLIBLE);
    ctx.encrypt_init(Some(Cipher::aes_256_ecb()), Some(key), None)
        .expect(INFALLIBLE);
    ctx.set_padding(false);

    // Every block goes through the same ECB context; ECB blocks are independent.
    let mut aes = |input: &[u8; BLOCK_LEN], output: &mut [u8]| {
        let mut scratch = Zeroizing::new([0u8; 2 * BLOCK_LEN]);
        ctx.cipher_update(input, Some(scratch.as_mut_slice()))
            .expect(INFALLIBLE);
        output.copy_from_slice(&scratch[..BLOCK_LEN]);
    };

    let mut l = Zeroizing::new([0u8; BLOCK_LEN]);
    aes(&[0u8; BLOCK_LEN], l.as_mut_slice());
    let k1 = Zeroizing::new(double(&l));

    let (derivation_nonce, gcm_nonce) = nonce.split_at(DERIVATION_NONCE_LEN);
    let mut derived = Zeroizing::new([0u8; KEY_LEN]);
    let (half_1, half_2) = derived.split_at_mut(BLOCK_LEN);
    aes(&counter_block(&k1, PREFIX_1, derivation_nonce), half_1);
    aes(&counter_block(&k1, PREFIX_2, derivation_nonce), half_2);

    let gcm_nonce = gcm_nonce.try_into().expect("24 - 12 = 12 nonce bytes");
    (derived, gcm_nonce)
}

/// Doubling in GF(2^128): `L << 1`, reduced by `RB` when the top bit falls off.
fn double(l: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut out = [0u8; BLOCK_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        let carry = l.get(i + 1).map_or(0, |next| next >> 7);
        *byte = (l[i] << 1) | carry;
    }

    // Constant time: mask is 0xff iff the MSB of L was set.
    let mask = 0u8.wrapping_sub(l[0] >> 7);
    out[BLOCK_LEN - 1] ^= RB & mask;
    out
}

/// `K1 XOR (prefix || nonce[..12])`.
fn counter_block(
    k1: &[u8; BLOCK_LEN],
    prefix: [u8; 4],
    derivation_nonce: &[u8],
) -> Zeroizing<[u8; BLOCK_LEN]> {
    let mut block = Zeroizing::new([0u8; BLOCK_LEN]);
    block[..prefix.len()].copy_from_slice(&prefix);
    block[prefix.len()..].copy_from_slice(derivation_nonce);
    for (b, k) in block.iter_mut().zip(k1) {
        *b ^= k;
    }
    block
}
