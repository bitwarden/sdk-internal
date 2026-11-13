/// Fills `dst` from the OpenSSL CSPRNG.
pub(crate) fn fill_bytes(dst: &mut [u8]) {
    ::openssl::rand::rand_bytes(dst).expect("OpenSSL CSPRNG must not fail");
}
