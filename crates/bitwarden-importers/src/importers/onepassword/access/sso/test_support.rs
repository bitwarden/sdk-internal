//! The generated vectors and the mock server of an enrolled device, shared by the tests of the
//! SSO submodules.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use bitwarden_api_base::new_http_client;
use data_encoding::{BASE64, BASE64URL_NOPAD, HEXLOWER};
use serde::Deserialize;
use serde_json::{Value, json};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, matchers};

use super::{
    super::{rest::RestClient, wire::EncryptedEnvelope},
    Timing,
    cpace::{
        EnrollmentSession, SignIn, enrolled_device_msg_a, enrolled_device_tag_a, expected_tag_b,
        share_credentials,
    },
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
    pub tag_a: String,
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

pub(super) fn sign_in(vectors: &CpaceVectors) -> SignIn<'_> {
    SignIn {
        username: &vectors.username,
        sign_in_address: &vectors.sign_in_address,
        sign_in_token: SIGN_IN_TOKEN,
    }
}

pub(super) fn session(vectors: &CpaceVectors) -> EnrollmentSession<'_> {
    EnrollmentSession {
        sign_in: sign_in(vectors),
        enrollment_uuid: &vectors.enrollment_uuid,
    }
}

pub(super) fn path(vectors: &CpaceVectors, method: &str) -> String {
    format!(
        "/api/v3/device/enrollments/{}/{}",
        vectors.enrollment_uuid, method
    )
}

/// Answers the `msga` request with the vector's message, standard base64 like the server.
pub(super) async fn mock_msga(server: &MockServer, vectors: &CpaceVectors) {
    mock_msga_json(server, vectors, &vectors.msga_json).await;
}

async fn mock_msga_json(server: &MockServer, vectors: &CpaceVectors, msga_json: &str) {
    server
        .register(
            Mock::given(matchers::method("POST"))
                .and(matchers::path(path(vectors, "cpace/msga")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "msga": BASE64.encode(msga_json.as_bytes()),
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
    mock_answers_to_msga(server, vectors).await;
}

/// All of [`mock_enrolled_device`] that comes after `msga`.
pub(super) async fn mock_answers_to_msga(server: &MockServer, vectors: &CpaceVectors) {
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
        ResponseTemplate::new(200).set_body_json(json!({
            "taga": BASE64URL_NOPAD.encode(&hex(&vectors.tag_a)),
        })),
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

/// Like [`mock_enrolled_device`], for a client that picks its own secret, as production does, and
/// enrolls at `sign_in_address` rather than the address of the vectors.
///
/// The enrolled device shows `codes` one after the other, each with a first message of its own. It
/// takes whatever `msgb` arrives and answers with its `taga`. A `tagb` that proves the same key
/// makes it share the credentials, encrypted under that key. Any other makes it show the next code,
/// like 1Password's own client after a wrong one. The server answers with the replaced first
/// message once more, so the client has to wait for the new one.
pub(super) async fn mock_enrolled_device_for_any_client(
    server: &MockServer,
    vectors: &CpaceVectors,
    sign_in_address: &str,
    codes: &[&str],
) {
    let ya_secret = hex_array(&vectors.ya_secret);
    let device = Arc::new(Mutex::new(EnrolledDevice {
        msgs_a: (0u8..)
            .zip(codes)
            .map(|(index, code)| {
                enrolled_device_msg_a(
                    &vectors.username,
                    sign_in_address,
                    &vectors.enrollment_uuid,
                    code,
                    &ya_secret,
                    &[3 + index; 16],
                    &[4 + index; 16],
                )
            })
            .collect(),
        shown: 0,
        replaced: false,
        msg_b: None,
        shared: false,
    }));
    let respond = |answer: fn(&mut EnrolledDevice, &[u8; 64], &Request) -> ResponseTemplate| {
        let device = device.clone();
        move |request: &Request| {
            answer(
                &mut device.lock().expect("not poisoned"),
                &ya_secret,
                request,
            )
        }
    };

    for (method, endpoint, answer) in [
        (
            "POST",
            "cpace/msga",
            respond(|device, _, _| device.send_msg_a()),
        ),
        (
            "PUT",
            "cpace/msgb",
            respond(|device, _, request| device.take_msg_b(request)),
        ),
        ("POST", "cpace/taga", respond(EnrolledDevice::send_tag_a)),
        ("PUT", "cpace/tagb", respond(EnrolledDevice::check_tag_b)),
    ] {
        server
            .register(
                Mock::given(matchers::method(method))
                    .and(matchers::path(path(vectors, endpoint)))
                    .respond_with(answer),
            )
            .await;
    }

    let bundle_json = vectors.credential_bundle_json.clone();
    server
        .register(
            Mock::given(matchers::method("POST"))
                .and(matchers::path(path(vectors, "share/credentials")))
                .respond_with(move |_: &Request| {
                    device
                        .lock()
                        .expect("not poisoned")
                        .share(&ya_secret, bundle_json.as_bytes())
                }),
        )
        .await;
}

/// The state of the enrolled device of [`mock_enrolled_device_for_any_client`].
struct EnrolledDevice {
    /// The first message for each code the device shows in turn.
    msgs_a: Vec<Vec<u8>>,
    /// The index of the code shown.
    shown: usize,
    /// Whether the code was just replaced and the server still has its first message.
    replaced: bool,
    msg_b: Option<Vec<u8>>,
    /// Whether the new device proved the key of the code shown.
    shared: bool,
}

impl EnrolledDevice {
    fn msg_a(&self) -> &[u8] {
        self.msgs_a.get(self.shown).expect("a code left to show")
    }

    fn msg_b(&self) -> &[u8] {
        self.msg_b.as_deref().expect("msgb arrives first")
    }

    fn send_msg_a(&mut self) -> ResponseTemplate {
        let msg_a = if std::mem::take(&mut self.replaced) {
            &self.msgs_a[self.shown - 1]
        } else {
            self.msg_a()
        };
        ResponseTemplate::new(200).set_body_json(json!({ "msga": BASE64.encode(msg_a) }))
    }

    fn take_msg_b(&mut self, request: &Request) -> ResponseTemplate {
        self.msg_b = Some(base64url_field(request, "msgb"));
        ResponseTemplate::new(200).set_body_json(json!({"success": 1}))
    }

    fn send_tag_a(&mut self, ya_secret: &[u8; 64], _: &Request) -> ResponseTemplate {
        let tag_a =
            enrolled_device_tag_a(ya_secret, self.msg_a(), self.msg_b()).expect("a valid msgb");
        ResponseTemplate::new(200).set_body_json(json!({ "taga": BASE64URL_NOPAD.encode(&tag_a) }))
    }

    /// The server takes any `tagb`, and only the device on the other end tells whether it fits.
    fn check_tag_b(&mut self, ya_secret: &[u8; 64], request: &Request) -> ResponseTemplate {
        let expected = expected_tag_b(ya_secret, self.msg_a(), self.msg_b()).expect("a valid msgb");
        if base64url_field(request, "tagb") == expected {
            self.shared = true;
        } else {
            self.shown += 1;
            self.replaced = true;
            self.msg_b = None;
        }
        ResponseTemplate::new(200).set_body_json(json!({"success": 1}))
    }

    /// The credentials once the key is proven, an empty answer before.
    fn share(&self, ya_secret: &[u8; 64], bundle_json: &[u8]) -> ResponseTemplate {
        if !self.shared {
            return ResponseTemplate::new(200);
        }
        let encrypted =
            share_credentials(ya_secret, self.msg_a(), self.msg_b(), bundle_json, &[7; 12])
                .expect("shares");
        ResponseTemplate::new(200).set_body_json(json!({ "encCreds": encrypted }))
    }
}

fn base64url_field(request: &Request, name: &str) -> Vec<u8> {
    let body: Value = request.body_json().expect("a JSON body");
    let value = body[name].as_str().expect("a string field");
    BASE64URL_NOPAD.decode(value.as_bytes()).expect("base64url")
}
