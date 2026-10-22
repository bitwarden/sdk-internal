//! The generated vectors and the mock server of an enrolled device, shared by the tests of the
//! SSO submodules.

use std::{collections::BTreeMap, time::Duration};

use bitwarden_api_base::new_http_client;
use data_encoding::{BASE64, BASE64URL_NOPAD, HEXLOWER};
use serde::Deserialize;
use serde_json::json;
use wiremock::{Mock, MockServer, Respond, ResponseTemplate, matchers};

use super::{
    super::{rest::RestClient, wire::EncryptedEnvelope},
    Timing,
};

pub(super) const SIGN_IN_TOKEN: &str = "SIGN_IN_TOKEN";

/// Generated test vectors, see `fixtures/sso-vectors.json`.
#[derive(Deserialize)]
pub(super) struct Vectors {
    pub cpace: CpaceVectors,
    pub leb128_prefix: BTreeMap<usize, String>,
    pub redirect: RedirectVectors,
}

/// Where the identity provider sends the browser back to.
#[derive(Deserialize)]
pub(super) struct RedirectVectors {
    pub url: String,
    pub code: String,
    pub state: String,
}

/// Binary values are lowercase hex.
#[derive(Deserialize)]
pub(super) struct CpaceVectors {
    pub username: String,
    pub sign_in_address: String,
    pub enrollment_uuid: String,
    pub verification_code: String,
    pub client_secret: String,
    pub ya_secret: String,
    pub msga_json: String,
    pub passcode_hash: String,
    pub first_hash: String,
    pub second_hash: String,
    pub msgb: String,
    pub auth_a: String,
    pub auth_b: String,
    pub tag_b: String,
    pub exchange_key: String,
    pub credential_bundle_json: String,
    pub encrypted_credentials: EncryptedEnvelope,
}

pub(super) fn vectors() -> Vectors {
    serde_json::from_str(include_str!("../fixtures/sso-vectors.json")).expect("the vectors parse")
}

pub(super) fn hex(s: &str) -> Vec<u8> {
    HEXLOWER.decode(s.as_bytes()).expect("valid hex")
}

pub(super) fn hex_array<const N: usize>(s: &str) -> [u8; N] {
    hex(s).try_into().expect("the expected length")
}

/// Timings short enough for the tests to wait them out.
pub(super) fn quick_timing() -> Timing {
    Timing {
        until_result_delay: Duration::from_millis(1),
        until_result_attempts: 20,
        enrollment_poll_interval: Duration::from_millis(1),
        enrollment_poll_timeout: Duration::from_millis(20),
    }
}

pub(super) fn rest_client(server: &MockServer) -> RestClient {
    RestClient::new(
        new_http_client(),
        format!("http://{}/api", server.address()),
        "1Password for Mac/81210036",
        "1Password for Mac/81210036",
        "op-user-agent",
    )
    .expect("valid headers")
}

pub(super) fn path(vectors: &CpaceVectors, method: &str) -> String {
    format!(
        "/api/v3/device/enrollments/{}/{}",
        vectors.enrollment_uuid, method
    )
}

/// Answers the `msga` request with the vector's message, standard base64 like the server.
pub(super) async fn mock_msga(server: &MockServer, vectors: &CpaceVectors) {
    server
        .register(
            Mock::given(matchers::method("POST"))
                .and(matchers::path(path(vectors, "cpace/msga")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "msga": BASE64.encode(vectors.msga_json.as_bytes()),
                })))
                .expect(1),
        )
        .await;
}

/// The polled endpoints answer one empty 200 before the real body.
async fn mock_empty_then_answer(server: &MockServer, path: String, answer: impl Respond + 'static) {
    server
        .register(
            Mock::given(matchers::method("POST"))
                .and(matchers::path(path.clone()))
                .respond_with(ResponseTemplate::new(200))
                .up_to_n_times(1),
        )
        .await;
    server
        .register(
            Mock::given(matchers::method("POST"))
                .and(matchers::path(path))
                .and(matchers::body_json(json!({"signInToken": SIGN_IN_TOKEN})))
                .respond_with(answer)
                .expect(1),
        )
        .await;
}

/// The central server relaying the enrolled device behind the vectors: it hands out `msga`,
/// accepts exactly the vector's `msgb` and `tagb`, and reports `taga` and the shared
/// credentials after one empty answer each.
pub(super) async fn mock_enrolled_device(server: &MockServer, vectors: &CpaceVectors) {
    mock_msga(server, vectors).await;

    server
        .register(
            Mock::given(matchers::method("PUT"))
                .and(matchers::path(path(vectors, "cpace/msgb")))
                .and(matchers::body_json(json!({
                    "signInToken": SIGN_IN_TOKEN,
                    "msgb": BASE64URL_NOPAD.encode(&hex(&vectors.msgb)),
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": 1})))
                .expect(1),
        )
        .await;

    mock_empty_then_answer(
        server,
        path(vectors, "cpace/taga"),
        ResponseTemplate::new(200)
            .set_body_json(json!({ "taga": BASE64URL_NOPAD.encode(&[7; 64]) })),
    )
    .await;

    server
        .register(
            Mock::given(matchers::method("PUT"))
                .and(matchers::path(path(vectors, "cpace/tagb")))
                .and(matchers::body_json(json!({
                    "signInToken": SIGN_IN_TOKEN,
                    "tagb": BASE64URL_NOPAD.encode(&hex(&vectors.tag_b)),
                })))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": 1})))
                .expect(1),
        )
        .await;

    mock_empty_then_answer(
        server,
        path(vectors, "share/credentials"),
        ResponseTemplate::new(200).set_body_json(json!({
            "encCreds": serde_json::to_value(&vectors.encrypted_credentials)
                .expect("the envelope serializes"),
        })),
    )
    .await;
}
