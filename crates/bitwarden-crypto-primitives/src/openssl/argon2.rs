use crate::{Error, argon2::Params};

/// Minimum salt length accepted by the RustCrypto backend (and OpenSSL).
const MIN_SALT_LEN: usize = 8;
/// Minimum tag length (RFC 9106 §3.1).
const MIN_OUTPUT_LEN: usize = 4;
/// Lane count range (RFC 9106 §3.1).
const MAX_PARALLELISM: u32 = (1 << 24) - 1;
/// Memory must cover at least 8 KiB blocks per lane (RFC 9106 §3.1).
const MIN_MEMORY_KIB_PER_LANE: u32 = 8;

/// Argon2id v0x13. Lanes run sequentially: OpenSSL only threads them after a process-wide
/// `OSSL_set_max_threads`, which this driver leaves alone.
pub(crate) fn argon2id(
    password: &[u8],
    salt: &[u8],
    params: &Params,
    out: &mut [u8],
) -> Result<(), Error> {
    validate(salt, params, out.len())?;

    ::openssl::kdf::argon2id(
        None,
        password,
        salt,
        None,
        None,
        params.iterations,
        params.parallelism,
        params.memory_kib,
        out,
    )
    .map_err(|_| Error::InvalidParameters)
}

/// Rejects the same parameters as the RustCrypto backend, before OpenSSL can clamp or adjust them.
fn validate(salt: &[u8], params: &Params, out_len: usize) -> Result<(), Error> {
    if salt.len() < MIN_SALT_LEN || out_len < MIN_OUTPUT_LEN {
        return Err(Error::InvalidParameters);
    }

    if params.iterations == 0 || params.parallelism == 0 || params.parallelism > MAX_PARALLELISM {
        return Err(Error::InvalidParameters);
    }

    let min_memory = params.parallelism.saturating_mul(MIN_MEMORY_KIB_PER_LANE);
    if params.memory_kib < min_memory {
        return Err(Error::InvalidParameters);
    }

    Ok(())
}
