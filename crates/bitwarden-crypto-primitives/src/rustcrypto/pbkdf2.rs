use std::num::NonZeroU32;

pub(crate) fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: NonZeroU32, out: &mut [u8]) {
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, salt, rounds.get(), out)
        .expect("HMAC accepts any key length");
}
