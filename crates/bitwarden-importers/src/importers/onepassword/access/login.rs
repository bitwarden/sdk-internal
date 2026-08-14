//! The password + Secret Key login state machine.
//!
//! One attempt runs: start a session (registering the device if the server asks), exchange SRP,
//! confirm the key, then complete authentication over the MAC-signed encrypted channel, driving 2FA
//! when the account requires it.

use serde_json::json;

use super::{
    account_key::AccountKey,
    credentials::Credentials,
    device::{ClientInfo, reauthorize_device, register_device},
    error::OnePasswordError,
    mac::MacSigner,
    opdata::{AesKey, decode64_loose},
    rest::RestClient,
    session::Session,
    srp::{self, SrpInfo},
    two_factor::{MfaOutcome, TwoFactorUi, perform_second_factor_authentication},
    wire::{AuthComplete, LoginInfo, MfaInfo, NewSession},
};

/// How many times the server may send us back to register or reauthorize the device before we give
/// up. One round is the normal case.
const MAX_DEVICE_ATTEMPTS: u32 = 2;
const AUTH_METHODS_ENDPOINT: &str = "v2/auth/methods";
const AUTH_START_ENDPOINT: &str = "v3/auth/start";
const AUTH_COMPLETE_ENDPOINT: &str = "v2/auth/complete";

/// The result of a single login attempt: a finished session, or a rejected OTP that asks for a full
/// restart.
pub(super) enum LoginOutcome {
    /// Authentication succeeded.
    Success(Box<Session>),
    /// The submitted TOTP code was rejected; the caller should retry from the start.
    BadOtp,
}

/// Confirms the account offers a given auth method.
pub(super) async fn fetch_auth_methods(
    username: &str,
    rest: &RestClient,
) -> Result<LoginInfo, OnePasswordError> {
    rest.post_json(AUTH_METHODS_ENDPOINT, json!({ "email": username }))
        .await
}

/// Runs one full login sequence: start a session, exchange SRP, verify the key, and drive 2FA if
/// the server asks for it.
pub(super) async fn login_attempt(
    credentials: &Credentials,
    account_key: &AccountKey,
    client_info: &ClientInfo,
    attempt: u32,
    ui: &dyn TwoFactorUi,
    rest: &RestClient,
) -> Result<LoginOutcome, OnePasswordError> {
    // Step 1: Request to initiate a new session
    let (session_id, srp_info) =
        start_new_session(credentials, account_key, client_info, rest).await?;

    // After a new session has been initiated, all the subsequent requests must be signed with the
    // session ID.
    let session_rest = rest.with_session_id(&session_id)?;

    // Step 2: Perform SRP exchange and verify key
    let session_key = srp::perform_and_verify(
        credentials,
        account_key,
        &srp_info,
        &session_id,
        &session_rest,
    )
    .await?;

    // Assign a request signer now that we have a key. All the following requests are expected to be
    // signed with the MAC.
    let mac_rest = session_rest.with_signer(MacSigner::new(&session_key));

    // Step 3: Verify the key with the server
    let mfa = verify_session_key(client_info, &session_key, &mac_rest).await?;

    // Step 4: Submit 2FA code if needed
    if let Some(mfa) = mfa {
        let outcome = perform_second_factor_authentication(
            &mfa,
            client_info,
            &session_key,
            attempt,
            ui,
            &mac_rest,
        )
        .await?;

        match outcome {
            MfaOutcome::Verified => {}
            MfaOutcome::BadOtp => return Ok(LoginOutcome::BadOtp),
        }
    }

    Ok(LoginOutcome::Success(Box::new(Session::new(
        session_key,
        mac_rest,
    ))))
}

/// Starts a new session, looping through device registration/reauthorization until the server
/// returns SRP parameters.
async fn start_new_session(
    credentials: &Credentials,
    account_key: &AccountKey,
    client_info: &ClientInfo,
    rest: &RestClient,
) -> Result<(String, SrpInfo), OnePasswordError> {
    let mut device_attempts = 0;
    loop {
        // Step 1: Request to initiate a new session
        let response: NewSession = rest
            .post_json(
                AUTH_START_ENDPOINT,
                json!({
                    "email": credentials.username,
                    "skformat": account_key.format,
                    "skid": account_key.uuid,
                    "deviceUuid": client_info.device_uuid,
                }),
            )
            .await?;

        // Step 2: We could be either done at this point, or the server could ask us to register or
        // reauthorize the device.
        match response.status.as_str() {
            // Done. For a previously unknown device ID this should never happen on a first try,
            // though.
            "ok" => {
                if response.key_format.as_deref() != Some(account_key.format.as_str())
                    || response.key_uuid.as_deref() != Some(account_key.uuid.as_str())
                {
                    return Err(OnePasswordError::BadCredentials);
                }

                let auth = response.auth.ok_or_else(|| {
                    OnePasswordError::Internal(
                        "missing SRP parameters in the start response".into(),
                    )
                })?;
                let srp_info = SrpInfo::new(
                    auth.method,
                    auth.algorithm,
                    auth.iterations,
                    decode64_loose(&auth.salt)?,
                )?;
                return Ok((response.session_id, srp_info));
            }
            // "Device deleted" should never really happen, unless we managed to guess a device UUID
            // that was previously registered and then deleted. Unlikely.
            status @ ("device-not-registered" | "device-deleted") => {
                device_attempts += 1;
                if device_attempts > MAX_DEVICE_ATTEMPTS {
                    return Err(OnePasswordError::Internal(format!(
                        "the server still reports the device as '{status}' after \
                         {MAX_DEVICE_ATTEMPTS} attempts"
                    )));
                }

                let session_rest = rest.with_session_id(&response.session_id)?;
                if status == "device-not-registered" {
                    register_device(client_info, &session_rest).await?;
                } else {
                    reauthorize_device(client_info, &session_rest).await?;
                }
            }
            other => {
                return Err(OnePasswordError::Internal(format!(
                    "failed to start a new session, unsupported status '{other}'"
                )));
            }
        }
    }
}

/// Completes authentication over the MAC-signed, encrypted channel, returning the enabled 2FA
/// methods when the account needs a second factor.
async fn verify_session_key(
    client_info: &ClientInfo,
    session_key: &AesKey,
    rest: &RestClient,
) -> Result<Option<MfaInfo>, OnePasswordError> {
    let params = json!({
        "client": client_info.client_id(),
        "device": client_info.device_body(),
    });
    let response: AuthComplete = rest
        .post_encrypted_json(AUTH_COMPLETE_ENDPOINT, params, session_key)
        .await?;
    Ok(response.mfa)
}

#[cfg(test)]
mod tests {
    use bitwarden_api_base::new_http_client;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    use super::*;

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

    fn credentials() -> Credentials {
        Credentials {
            username: "user@example.com".into(),
            password: "password".into(),
            account_key: "A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9".into(),
            domain: "my.1password.com".into(),
            device_uuid: "device-uuid".into(),
        }
    }

    fn account_key() -> AccountKey {
        AccountKey::parse(&credentials().account_key).expect("valid account key")
    }

    fn start_response(status: &str) -> serde_json::Value {
        json!({"status": status, "sessionID": "SESSION"})
    }

    fn ok_start_response() -> serde_json::Value {
        json!({
            "status": "ok",
            "sessionID": "SESSION",
            "accountKeyFormat": "A3",
            "accountKeyUuid": "RTN9SA",
            "userAuth": {
                "method": "SRPg-4096",
                "alg": "PBES2g-HS256",
                "iterations": 10,
                "salt": "c2FsdHNhbHRzYWx0",
            },
        })
    }

    #[tokio::test]
    async fn fetches_the_auth_methods() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v2/auth/methods"))
                    .and(matchers::body_json(json!({"email": "user@example.com"})))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(json!({"authMethods": [{"type": "PASSWORD+SK"}]})),
                    )
                    .expect(1),
            )
            .await;

        let info = fetch_auth_methods("user@example.com", &client(&server))
            .await
            .expect("methods are listed");

        assert_eq!(info.auth_methods[0].kind, "PASSWORD+SK");
        server.verify().await;
    }

    #[tokio::test]
    async fn start_registers_an_unknown_device_then_retries() {
        let server = MockServer::start().await;
        // The first start says the device is unknown, the second succeeds. wiremock matches the
        // most recently registered mock first, so register the success last.
        server
            .register(
                Mock::given(matchers::path("/api/v3/auth/start"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(start_response("device-not-registered")),
                    )
                    .up_to_n_times(1)
                    .expect(1),
            )
            .await;
        server
            .register(
                Mock::given(matchers::path("/api/v1/device"))
                    .and(matchers::method("POST"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": 1})))
                    .expect(1),
            )
            .await;
        server
            .register(
                Mock::given(matchers::path("/api/v3/auth/start"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(ok_start_response()))
                    .expect(1),
            )
            .await;

        let (session_id, srp_info) = start_new_session(
            &credentials(),
            &account_key(),
            &ClientInfo::for_desktop("device-uuid"),
            &client(&server),
        )
        .await
        .expect("session starts after registering the device");

        assert_eq!(session_id, "SESSION");
        assert_eq!(
            srp_info,
            SrpInfo::new(
                "SRPg-4096".into(),
                "PBES2g-HS256".into(),
                10,
                b"saltsaltsalt".to_vec(),
            )
            .expect("supported parameters")
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn start_gives_up_when_the_device_never_registers() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v3/auth/start"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(start_response("device-not-registered")),
                    )
                    .expect(u64::from(MAX_DEVICE_ATTEMPTS) + 1),
            )
            .await;
        server
            .register(
                Mock::given(matchers::path("/api/v1/device"))
                    .and(matchers::method("POST"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": 1})))
                    .expect(u64::from(MAX_DEVICE_ATTEMPTS)),
            )
            .await;

        let error = start_new_session(
            &credentials(),
            &account_key(),
            &ClientInfo::for_desktop("device-uuid"),
            &client(&server),
        )
        .await
        .expect_err("gives up instead of registering the device forever");

        assert!(
            error.to_string().contains("device-not-registered"),
            "unexpected error: {error}"
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn start_rejects_a_mismatching_account_key() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v3/auth/start"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "status": "ok",
                        "sessionID": "SESSION",
                        "accountKeyFormat": "A3",
                        "accountKeyUuid": "OTHERS",
                    })))
                    .expect(1),
            )
            .await;

        let error = start_new_session(
            &credentials(),
            &account_key(),
            &ClientInfo::for_desktop("device-uuid"),
            &client(&server),
        )
        .await
        .expect_err("the server knows a different Secret Key");

        assert!(matches!(error, OnePasswordError::BadCredentials));
        server.verify().await;
    }

    #[tokio::test]
    async fn start_reports_an_unknown_status() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path("/api/v3/auth/start"))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(start_response("who-knows")),
                    )
                    .expect(1),
            )
            .await;

        let error = start_new_session(
            &credentials(),
            &account_key(),
            &ClientInfo::for_desktop("device-uuid"),
            &client(&server),
        )
        .await
        .expect_err("unknown status");

        assert!(error.to_string().contains("who-knows"));
        server.verify().await;
    }
}
