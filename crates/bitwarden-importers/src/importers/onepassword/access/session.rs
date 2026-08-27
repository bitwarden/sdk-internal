//! The signed channel a completed login leaves behind.

use super::{opdata::AesKey, rest::RestClient};

/// The session key and a client that MAC-signs and encrypts every request with it.
pub(super) struct Session {
    pub key: AesKey,
    pub rest: RestClient,
}

impl Session {
    pub(crate) fn new(key: AesKey, rest: RestClient) -> Session {
        Session { key, rest }
    }
}
