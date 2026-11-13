use std::num::NonZeroU32;

use ::openssl::{hash::MessageDigest, pkcs5};

pub(crate) fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: NonZeroU32, out: &mut [u8]) {
    let rounds = usize::try_from(rounds.get()).expect("u32 fits in usize");
    pkcs5::pbkdf2_hmac(password, salt, rounds, MessageDigest::sha256(), out)
        .expect("PBKDF2-HMAC accepts any password, salt and output length");
}
