//! Two-factor authentication: the callback the caller implements and the TOTP exchange that
//! drives it.
//!
//! Only TOTP (Google Authenticator) is implemented. WebAuthn and Duo extend [`TwoFactorUi`] later.

use async_trait::async_trait;
use serde::de::IgnoredAny;
use serde_json::json;

use super::{
    device::ClientInfo, error::OnePasswordError, opdata::AesKey, rest::RestClient, wire::MfaInfo,
};

const MFA_ENDPOINT: &str = "v1/auth/mfa";

/// The outcome of a two-factor prompt.
pub enum TotpResult {
    /// A passcode entered (or generated) by the user.
    Code(String),
    /// The user declined to provide a passcode.
    Cancel,
}

/// Callback for interactive two-factor authentication.
#[async_trait]
pub trait TwoFactorUi: Send + Sync {
    /// Provides a TOTP passcode for the given zero-based attempt. Each wrong code restarts the
    /// login, so `attempt` grows as the user retries.
    async fn provide_totp(&self, attempt: u32) -> TotpResult;
}

/// The result of submitting a second factor: verified, or a rejected code that asks for a restart.
#[derive(Debug)]
pub(super) enum MfaOutcome {
    /// The code was accepted and the session is authenticated.
    Verified,
    /// The code was rejected. 1Password invalidates the session, so the login has to start over.
    BadOtp,
}

/// Prompts for and submits a TOTP code. WebAuthn and Duo are not supported yet.
pub(super) async fn perform_second_factor_authentication(
    mfa: &MfaInfo,
    client_info: &ClientInfo,
    session_key: &AesKey,
    attempt: u32,
    ui: &dyn TwoFactorUi,
    rest: &RestClient,
) -> Result<MfaOutcome, OnePasswordError> {
    if !mfa.totp_enabled() {
        return Err(OnePasswordError::Unsupported(format!(
            "account requires an unsupported 2FA method (offered: {})",
            mfa.enabled_methods().join(", ")
        )));
    }

    let passcode = match ui.provide_totp(attempt).await {
        TotpResult::Code(passcode) => passcode,
        TotpResult::Cancel => return Err(OnePasswordError::TwoFactorFailed),
    };

    match submit_totp(client_info, session_key, &passcode, rest).await {
        Ok(()) => Ok(MfaOutcome::Verified),
        // 1Password reports a wrong code as a generic auth error; treat it as a retryable bad code.
        Err(OnePasswordError::BadCredentials) => Ok(MfaOutcome::BadOtp),
        Err(error) => Err(error),
    }
}

/// Submits a TOTP code to `v1/auth/mfa`. The remember-me token in the response is ignored (one-shot
/// import).
async fn submit_totp(
    client_info: &ClientInfo,
    session_key: &AesKey,
    passcode: &str,
    rest: &RestClient,
) -> Result<(), OnePasswordError> {
    let params = json!({
        "sessionID": session_key.id,
        "client": client_info.client_id(),
        "totp": { "code": passcode },
    });
    let _: IgnoredAny = rest
        .post_encrypted_json(MFA_ENDPOINT, params, session_key)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitwarden_api_base::new_http_client;
    use rand::Rng;
    use serde_json::Value;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    use super::{super::opdata::decode64_loose, *};

    struct ScriptedUi {
        result: TotpResult,
    }

    impl ScriptedUi {
        fn code(passcode: &str) -> ScriptedUi {
            ScriptedUi {
                result: TotpResult::Code(passcode.into()),
            }
        }

        fn cancel() -> ScriptedUi {
            ScriptedUi {
                result: TotpResult::Cancel,
            }
        }
    }

    #[async_trait]
    impl TwoFactorUi for ScriptedUi {
        async fn provide_totp(&self, _attempt: u32) -> TotpResult {
            match &self.result {
                TotpResult::Code(passcode) => TotpResult::Code(passcode.clone()),
                TotpResult::Cancel => TotpResult::Cancel,
            }
        }
    }

    fn session_key() -> AesKey {
        AesKey::new(
            "SESSION",
            decode64_loose("WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM").expect("valid key"),
        )
    }

    fn client(server: &MockServer) -> RestClient {
        RestClient::new(
            new_http_client(),
            format!("http://{}/api", server.address()),
            "client-id",
            "user-agent",
            "op-user-agent",
        )
        .expect("valid headers")
    }

    fn mfa(json: &str) -> MfaInfo {
        serde_json::from_str(json).expect("valid mfa info")
    }

    /// Encrypts `plaintext` for the session key so the mock can answer like the real server does.
    fn encrypted_body(key: &AesKey, plaintext: &[u8]) -> Value {
        let mut iv = [0u8; 12];
        bitwarden_random::rng().fill_bytes(&mut iv);
        let envelope = key.encrypt(plaintext, &iv).expect("encrypts");
        serde_json::to_value(&envelope).expect("serializes")
    }

    #[tokio::test]
    async fn submits_the_code_from_the_callback() {
        let key = session_key();
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v1/auth/mfa"))
                    .and(matchers::method("POST"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(encrypted_body(&key, br#"{"sessionID":"SESSION"}"#)),
                    )
                    .expect(1),
            )
            .await;

        let outcome = perform_second_factor_authentication(
            &mfa(r#"{"totp":{"enabled":true}}"#),
            &ClientInfo::for_desktop("device-uuid"),
            &key,
            0,
            &ScriptedUi::code("123456"),
            &client(&server),
        )
        .await
        .expect("2FA completes");

        assert!(matches!(outcome, MfaOutcome::Verified));
        server.verify().await;
    }

    #[tokio::test]
    async fn a_rejected_code_asks_for_a_restart() {
        let key = session_key();
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v1/auth/mfa"))
                    .respond_with(ResponseTemplate::new(401).set_body_json(
                        serde_json::json!({"errorCode": 102, "errorMessage": "bad code"}),
                    ))
                    .expect(1),
            )
            .await;

        let outcome = perform_second_factor_authentication(
            &mfa(r#"{"totp":{"enabled":true}}"#),
            &ClientInfo::for_desktop("device-uuid"),
            &key,
            1,
            &ScriptedUi::code("000000"),
            &client(&server),
        )
        .await
        .expect("a bad code is not a hard failure");

        assert!(matches!(outcome, MfaOutcome::BadOtp));
        server.verify().await;
    }

    #[tokio::test]
    async fn cancelling_the_prompt_fails_the_login() {
        let server = MockServer::start().await;

        let error = perform_second_factor_authentication(
            &mfa(r#"{"totp":{"enabled":true}}"#),
            &ClientInfo::for_desktop("device-uuid"),
            &session_key(),
            0,
            &ScriptedUi::cancel(),
            &client(&server),
        )
        .await
        .expect_err("the user declined");

        assert!(matches!(error, OnePasswordError::TwoFactorFailed));
    }

    #[tokio::test]
    async fn rejects_accounts_without_totp() {
        let server = MockServer::start().await;

        let error = perform_second_factor_authentication(
            &mfa(r#"{"totp":{"enabled":false},"duo":{"enabled":true}}"#),
            &ClientInfo::for_desktop("device-uuid"),
            &session_key(),
            0,
            &ScriptedUi::code("123456"),
            &client(&server),
        )
        .await
        .expect_err("Duo is not supported");

        assert!(matches!(error, OnePasswordError::Unsupported(_)));
        assert!(error.to_string().contains("Duo"));
    }
}
