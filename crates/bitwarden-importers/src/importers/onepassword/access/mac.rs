//! `X-AgileBits-MAC` request signer.

use std::sync::atomic::{AtomicU32, Ordering};

use data_encoding::BASE64URL_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::Sha256;
use url::Url;

use super::{error::OnePasswordError, opdata::AesKey};

const SESSION_HMAC_SECRET: &str = "He never wears a Mac, in the pouring rain. Very strange.";

/// Signs requests with the per-session MAC header, bumping the request id on each signature.
pub(super) struct MacSigner {
    session_id: String,
    salt: [u8; 32],
    request_id: AtomicU32,
}

impl MacSigner {
    /// Creates a signer from the session key, starting from a random request id.
    pub(super) fn new(session_key: &AesKey) -> MacSigner {
        Self::with_request_id(session_key, bitwarden_random::rng().next_u32())
    }

    fn with_request_id(session_key: &AesKey, request_id: u32) -> MacSigner {
        MacSigner {
            session_id: session_key.id.clone(),
            salt: calculate_session_hmac_salt(&session_key.key),
            request_id: AtomicU32::new(request_id),
        }
    }

    /// Returns the `X-AgileBits-MAC` header value for a request and takes the next request id.
    ///
    /// The id only has to differ between requests, so nothing needs ordering against other threads.
    pub(super) fn sign(&self, url: &str, method: &str) -> Result<String, OnePasswordError> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed);

        let message = self.calculate_auth_message(url, method, id)?;
        Ok(calculate_auth_signature(&self.salt, &message, id))
    }

    /// `sessionId|METHOD|host/path?query|v1|requestId`.
    fn calculate_auth_message(
        &self,
        url: &str,
        method: &str,
        request_id: u32,
    ) -> Result<String, OnePasswordError> {
        let parsed = Url::parse(url)
            .map_err(|_| OnePasswordError::Internal(format!("invalid url '{url}'")))?;
        let host = parsed.host_str().unwrap_or("");
        let path = parsed.path().trim_start_matches('/');
        let query = parsed.query().unwrap_or("");

        Ok(format!(
            "{}|{}|{}/{}?{}|v1|{}",
            self.session_id,
            method.to_uppercase(),
            host,
            path,
            query,
            request_id
        ))
    }
}

/// `v1|requestId|b64url(HMAC-SHA256(salt, message)[0..12])`.
fn calculate_auth_signature(salt: &[u8], auth_message: &str, request_id: u32) -> String {
    let hash = hmac_sha256(salt, auth_message.as_bytes());
    let hash12 = BASE64URL_NOPAD.encode(&hash[..12]);
    format!("v1|{request_id}|{hash12}")
}

/// `HMAC-SHA256(sessionKey, secret)`.
fn calculate_session_hmac_salt(session_key: &[u8]) -> [u8; 32] {
    hmac_sha256(session_key, SESSION_HMAC_SECRET.as_bytes())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;

    use super::{super::opdata::decode64_loose, *};

    const SESSION_KEY: &str = "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM";

    fn signer() -> MacSigner {
        let key = AesKey::new(
            "PBXONDZUWVCJFAV25C7XR7IYDQ",
            decode64_loose(SESSION_KEY).expect("valid key"),
        );
        MacSigner::with_request_id(&key, 842346063)
    }

    #[test]
    fn sign_returns_headers_with_signature() {
        let signature = signer()
            .sign("https://my.1password.com/api/v1/auth/verify", "POST")
            .expect("signs");
        assert_eq!(signature, "v1|842346063|xv-fEAYowunpH4V-");
    }

    #[test]
    fn sign_returns_signature_for_url_with_query() {
        let signature = signer()
            .sign(
                "https://my.1password.com/api/v1/account?attrs=billing,counts,groups,invite,me,settings,tier,user-flags,users,vaults",
                "GET",
            )
            .expect("signs");
        assert_eq!(signature, "v1|842346063|UyjKq0HAmjB5j7kF");
    }

    #[test]
    fn sign_increments_the_counter() {
        let signer = signer();
        let first = signer
            .sign("https://my.1password.com/api/v1/auth/verify", "POST")
            .expect("signs");
        let second = signer
            .sign("https://my.1password.com/api/v1/auth/verify", "POST")
            .expect("signs");

        assert_ne!(first, second);

        let seed = |s: &str| -> u32 {
            s.split('|')
                .nth(1)
                .expect("seed field")
                .parse()
                .expect("u32")
        };
        assert_eq!(seed(&first) + 1, seed(&second));
    }

    #[test]
    fn calculates_session_hmac_salt() {
        let key = decode64_loose(SESSION_KEY).expect("valid key");
        assert_eq!(
            HEXLOWER.encode(&calculate_session_hmac_salt(&key)),
            "cce080cc9b3eaeaa9b6e621e1b4c4d2048babe16e40b0576fc2520c26473b9ac"
        );
    }

    #[test]
    fn new_starts_from_a_random_request_id() {
        let key = AesKey::new(
            "PBXONDZUWVCJFAV25C7XR7IYDQ",
            decode64_loose(SESSION_KEY).expect("valid key"),
        );
        let ids: Vec<u32> = (0..4)
            .map(|_| MacSigner::new(&key).request_id.into_inner())
            .collect();
        assert!(ids.iter().any(|id| *id != ids[0]));
    }
}
