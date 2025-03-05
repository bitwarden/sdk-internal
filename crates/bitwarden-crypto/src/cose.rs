use coset::iana;

pub(crate) const XCHACHA20_POLY1305: i64 = -70000;
pub(crate) const ARGON2_ID: i64 = -70001;
pub(crate) const PBKDF2: i64 = -70002;

pub(crate) const SYMMETRIC_KEY: i64 = iana::SymmetricKeyParameter::K as i64;