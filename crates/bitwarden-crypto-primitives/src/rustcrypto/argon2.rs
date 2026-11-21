use argon2::{Algorithm, Argon2, Version};

use crate::{Error, argon2::Params};

pub(crate) fn argon2id_v13(
    password: &[u8],
    salt: &[u8],
    params: &Params,
    out: &mut [u8],
) -> Result<(), Error> {
    let params = argon2::Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(out.len()),
    )
    .map_err(|_| Error::InvalidParameters)?;

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, out)
        .map_err(|_| Error::InvalidParameters)
}
