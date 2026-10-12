//! A fake 1Password server for the tests of the whole SSO login. It knows one SSO account, runs the
//! server side of SRP for real, and serves the account's keysets and one vault, encrypted with the
//! session key.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU32, Ordering},
};

use bitwarden_api_base::new_http_client;
use data_encoding::BASE64URL_NOPAD;
use serde_json::{Value, json};
use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers};

use super::{
    super::{
        device::ClientInfo,
        keychain::MASTER_KEY_ID,
        mac::MacSigner,
        opdata::{AesKey, Encrypted, decode64_loose},
        rest::RestClient,
        srp::TestServer,
        wire::{CredentialBundle, EncryptedEnvelope},
    },
    test_support::{SIGN_IN_TOKEN, vectors},
};

pub(super) const USERNAME: &str = "user@example.com";
const DEVICE_UUID: &str = "device-uuid";
const USER_UUID: &str = "USERUUID";
const ACCOUNT_UUID: &str = "ACCOUNTUUID";
pub(super) const SSO_SESSION_UUID: &str = "SESSIONUUID";
const VAULT_UUID: &str = "VAULTUUID";

/// What the identity provider step of the fake account looks like.
pub(super) const SSO_LOGIN_URL: &str = "https://idp.example.com/authorize?client_id=abc\
    &redirect_uri=https%3A%2F%2Facme.1password.com%2Fsso%2Foidc%2Fredirect%2F";
pub(super) const REDIRECTED_TO: &str =
    "https://acme.1password.com/sso/oidc/redirect/#code=c0de&state=st4te&session_state=other";
const CODE: &str = "c0de";
const STATE: &str = "st4te";

const KEY_UUID: &str = "KEYUUID";
const SALT: &[u8] = b"salt";
const KEYSET_UUID: &str = "szerdhg2ww2ahjo4ilz57x7cce";
const VAULT_KEY_ID: &str = "VAULTKEY";
const IV: [u8; 12] = [1; 12];

pub(super) fn client_info() -> ClientInfo {
    ClientInfo::for_desktop(DEVICE_UUID)
}

/// The credential bundle of the account, the one every fixture of the vectors carries.
fn bundle() -> CredentialBundle {
    serde_json::from_str(&vectors().cpace.credential_bundle_json).expect("a valid bundle")
}

/// The account unlock key of the fake account.
pub(super) fn account_unlock_key() -> Vec<u8> {
    decode64_loose(&bundle().auk.k).expect("valid base64")
}

/// What `v3/auth/sso/oidc/verify` answers, `state` being what the server says about the device.
pub(super) fn verify_response(state: &str) -> Value {
    json!({
        "type": state,
        "user": {
            "sessionUuid": SSO_SESSION_UUID,
            "accountUuid": ACCOUNT_UUID,
            "userUuid": USER_UUID,
            "email": USERNAME,
        },
        "ssoAuth": {
            "signInTokenDetails": {
                "token": SIGN_IN_TOKEN,
                "publicKey": "PUBLICKEY",
                "exp": "2030-01-01T00:00:00Z",
            },
        },
    })
}

/// A server with an SSO account on it. `start` sets up what follows the identity provider step.
pub(super) struct FakeServer {
    pub(super) mock: MockServer,
    state: Arc<State>,
}

/// What the request handlers share.
struct State {
    srp: TestServer,
    shared_a: Mutex<Option<String>>,
    session_key: Mutex<Option<[u8; 32]>>,
    next_request_id: AtomicU32,
    mfa: Value,
    account: Value,
    keysets: Value,
    items: Value,
}

impl FakeServer {
    /// Starts a server that signs a device in without a second factor.
    pub(super) async fn start() -> FakeServer {
        FakeServer::start_with(Value::Null).await
    }

    /// Starts a server that asks for a second factor, `mfa` being the methods it offers.
    pub(super) async fn start_with_mfa(mfa: Value) -> FakeServer {
        FakeServer::start_with(mfa).await
    }

    async fn start_with(mfa: Value) -> FakeServer {
        let bundle = bundle();
        let srp_x = decode64_loose(&bundle.srpx).expect("valid base64");
        let unlock_key = AesKey::new(MASTER_KEY_ID, account_unlock_key());
        let (account, keysets, items) = vault(&unlock_key);

        let state = Arc::new(State {
            srp: TestServer::new(&srp_x, &[0x33; 32], USERNAME, KEY_UUID, SALT),
            shared_a: Mutex::new(None),
            session_key: Mutex::new(None),
            next_request_id: AtomicU32::new(1),
            mfa,
            account,
            keysets,
            items,
        });

        let server = FakeServer {
            mock: MockServer::start().await,
            state,
        };
        server.mock_login_after_sso().await;
        server.mock_download().await;
        server
    }

    /// A client for the server as it is built before the login info is known.
    pub(super) fn rest(&self) -> RestClient {
        let info = client_info();
        RestClient::new(
            new_http_client(),
            format!("{}/api", self.sign_in_address()),
            &info.client_id(),
            &info.user_agent,
            &info.op_user_agent,
        )
        .expect("valid headers")
    }

    /// The address the account signs in at, which is also where its SSO API is.
    pub(super) fn sign_in_address(&self) -> String {
        format!("http://{}", self.mock.address())
    }

    /// The paths of the requests received so far, oldest first.
    pub(super) async fn requested_paths(&self) -> Vec<String> {
        self.mock
            .received_requests()
            .await
            .expect("requests are recorded")
            .iter()
            .map(|request| request.url.path().to_string())
            .collect()
    }

    /// `v2/auth/methods`, with or without the SSO method.
    pub(super) async fn mock_login_info(&self, with_sso: bool) {
        let mut auth_methods = vec![json!({"type": "PASSWORD+SK"})];
        if with_sso {
            auth_methods.push(json!({"type": "OIDC", "provider": "Acme"}));
        }

        self.mock
            .register(
                Mock::given(matchers::method("POST"))
                    .and(matchers::path("/api/v2/auth/methods"))
                    .and(matchers::body_json(json!({"email": USERNAME})))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "userUuid": USER_UUID,
                        "signInAddress": self.sign_in_address(),
                        "authMethods": auth_methods,
                    })))
                    .expect(1),
            )
            .await;
    }

    /// `v3/auth/sso/oidc/start`, which has to be sent the user and nothing else.
    pub(super) async fn mock_sso_start(&self) {
        self.mock
            .register(
                Mock::given(matchers::method("POST"))
                    .and(matchers::path("/api/v3/auth/sso/oidc/start"))
                    .and(matchers::body_json(json!({"userUuid": USER_UUID})))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .set_body_json(json!({"authRedirect": SSO_LOGIN_URL})),
                    )
                    .expect(1),
            )
            .await;
    }

    /// `v3/auth/sso/oidc/verify`, which answers `verified` to the code and state the identity
    /// provider redirected with.
    pub(super) async fn mock_sso_verify(&self, verified: Value) {
        self.mock
            .register(
                Mock::given(matchers::method("POST"))
                    .and(matchers::path("/api/v3/auth/sso/oidc/verify"))
                    .and(matchers::body_json(json!({
                        "code": CODE,
                        "state": STATE,
                        "device": client_info().sso_verify_device_body(),
                    })))
                    .respond_with(ResponseTemplate::new(200).set_body_json(verified))
                    .expect(1),
            )
            .await;
    }

    /// The requests that follow the SSO session, which all carry its id in a header.
    async fn mock_login_after_sso(&self) {
        let with_session_id = |method: &str, path: &str| {
            Mock::given(matchers::method(method))
                .and(matchers::path(path))
                .and(matchers::header("x-agilebits-session-id", SSO_SESSION_UUID))
        };

        self.mock
            .register(
                with_session_id("POST", "/api/v3/auth/start")
                    .and(matchers::body_json(json!({
                        "signInToken": SIGN_IN_TOKEN,
                        "deviceUuid": DEVICE_UUID,
                        "userUuid": USER_UUID,
                    })))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                        "status": "ok",
                        "sessionID": "IGNORED",
                        "accountKeyFormat": "A3",
                        "accountKeyUuid": KEY_UUID,
                        "userAuth": {
                            "method": "SRPg-4096",
                            "alg": "PBES2g-HS256",
                            "iterations": 100000,
                            "salt": BASE64URL_NOPAD.encode(SALT),
                        },
                    }))),
            )
            .await;

        let state = self.state.clone();
        self.mock
            .register(
                with_session_id("POST", "/api/v2/auth")
                    .respond_with(move |request: &Request| state.exchange_a(request)),
            )
            .await;

        let state = self.state.clone();
        self.mock
            .register(
                with_session_id("POST", "/api/v2/auth/confirm-key")
                    .respond_with(move |request: &Request| state.confirm_key(request)),
            )
            .await;

        let state = self.state.clone();
        self.mock
            .register(
                with_session_id("POST", "/api/v2/auth/complete")
                    .respond_with(move |request: &Request| state.complete_auth(request)),
            )
            .await;
    }

    /// The account, its keysets and the items of its vault.
    async fn mock_download(&self) {
        let items_path = format!("/api/v1/vault/{VAULT_UUID}/0/items");
        for (path, body) in [
            ("/api/v1/account", &self.state.account),
            ("/api/v1/account/keysets", &self.state.keysets),
            (items_path.as_str(), &self.state.items),
        ] {
            let (state, body) = (self.state.clone(), body.clone());
            self.mock
                .register(
                    Mock::given(matchers::method("GET"))
                        .and(matchers::path(path))
                        .and(matchers::header("x-agilebits-session-id", SSO_SESSION_UUID))
                        .respond_with(move |request: &Request| {
                            state.encrypted_answer(request, &body)
                        }),
                )
                .await;
        }
    }
}

impl State {
    /// The session key, once the SRP exchange has established it.
    fn session_key(&self) -> Option<AesKey> {
        let key = (*self.session_key.lock().expect("not poisoned"))?;
        Some(AesKey::new(SSO_SESSION_UUID, key.to_vec()))
    }

    /// `v2/auth`: takes the client's `A` and answers with `B`.
    fn exchange_a(&self, request: &Request) -> ResponseTemplate {
        let Some(shared_a) = body_field(request, "userA") else {
            return reject("no userA in the request");
        };
        *self.shared_a.lock().expect("not poisoned") = Some(shared_a);

        ResponseTemplate::new(200).set_body_json(json!({ "userB": self.srp.shared_b() }))
    }

    /// `v2/auth/confirm-key`: checks the client's proof and answers with the server's.
    fn confirm_key(&self, request: &Request) -> ResponseTemplate {
        let shared_a = self.shared_a.lock().expect("not poisoned").clone();
        let (Some(shared_a), Some(client_hash)) =
            (shared_a, body_field(request, "clientVerifyHash"))
        else {
            return reject("no A yet, or no clientVerifyHash in the request");
        };

        match self.srp.confirm_key(&shared_a, &client_hash) {
            Some(server_hash) => {
                *self.session_key.lock().expect("not poisoned") = self.srp.session_key(&shared_a);
                ResponseTemplate::new(200).set_body_json(json!({ "serverVerifyHash": server_hash }))
            }
            None => ResponseTemplate::new(401),
        }
    }

    /// `v2/auth/complete`: expects the device descriptor of the SSO login.
    fn complete_auth(&self, request: &Request) -> ResponseTemplate {
        let (key, received) = match self.decrypt_signed_request(request) {
            Ok(decrypted) => decrypted,
            Err(why) => return reject(why),
        };

        let info = client_info();
        let expected = json!({
            "client": info.client_id(),
            "signInToken": SIGN_IN_TOKEN,
            "device": info.sso_complete_device_body(),
        });
        if received != expected {
            return reject(format!("unexpected complete request {received}"));
        }

        seal(&key, &json!({"mfa": self.mfa}))
    }

    /// Answers `body`, encrypted with the session key, to a signed request.
    fn encrypted_answer(&self, request: &Request, body: &Value) -> ResponseTemplate {
        match self.check_signature(request) {
            Ok(key) => seal(&key, body),
            Err(why) => reject(why),
        }
    }

    /// Checks the signature of a request, and decrypts its body with the session key.
    fn decrypt_signed_request(&self, request: &Request) -> Result<(AesKey, Value), String> {
        let key = self.check_signature(request)?;

        let envelope: EncryptedEnvelope = serde_json::from_slice(&request.body)
            .map_err(|_| "the body is not an envelope".to_string())?;
        let encrypted = Encrypted::parse(&envelope).map_err(|error| error.to_string())?;
        let plaintext = key.decrypt(&encrypted).map_err(|error| error.to_string())?;
        let body =
            serde_json::from_slice(&plaintext).map_err(|_| "the body is not JSON".to_string())?;
        Ok((key, body))
    }

    /// Checks that the request is signed with the session key as the next one of the session.
    /// The first is the `v2/auth/complete` and they count up from 1.
    fn check_signature(&self, request: &Request) -> Result<AesKey, String> {
        let key = self
            .session_key()
            .ok_or_else(|| "no session key yet".to_string())?;

        let id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let expected = MacSigner::with_request_id(&key, id)
            .sign(&requested_url(request), request.method.as_str())
            .map_err(|error| error.to_string())?;
        let signature = request
            .headers
            .get("x-agilebits-mac")
            .and_then(|value| value.to_str().ok());
        if signature != Some(expected.as_str()) {
            return Err(format!(
                "the request is not signed as request {id} of the session: {signature:?}"
            ));
        }

        Ok(key)
    }
}

fn seal(key: &AesKey, body: &Value) -> ResponseTemplate {
    let envelope = key
        .encrypt(body.to_string().as_bytes(), &IV)
        .expect("encrypts");
    ResponseTemplate::new(200).set_body_json(envelope)
}

/// The URL the client asked for. The URL of the request has no host of the server, so it comes
/// from the header.
fn requested_url(request: &Request) -> String {
    let host = request
        .headers
        .get("host")
        .and_then(|host| host.to_str().ok())
        .unwrap_or_default();
    let query = request
        .url
        .query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();

    format!("http://{host}{}{query}", request.url.path())
}

/// A rejection that says why, which the client surfaces in its error.
fn reject(why: impl ToString) -> ResponseTemplate {
    ResponseTemplate::new(400)
        .set_body_json(json!({"errorCode": 400, "errorMessage": why.to_string()}))
}

fn body_field(request: &Request, name: &str) -> Option<String> {
    let body: Value = request.body_json().ok()?;
    body[name].as_str().map(str::to_string)
}

/// The account, keysets and items responses of a small account: one keyset under the account
/// unlock key, and one vault with one item under that.
fn vault(account_unlock_key: &AesKey) -> (Value, Value, Value) {
    let keyset_key = AesKey::new(KEYSET_UUID, vec![9; 32]);
    let vault_key = AesKey::new(VAULT_KEY_ID, vec![10; 32]);

    let seal = |key: &AesKey, plaintext: &[u8]| {
        serde_json::to_value(key.encrypt(plaintext, &IV).expect("encrypts")).expect("serializes")
    };
    let key_json =
        |key: &AesKey| json!({"kid": key.id, "k": BASE64URL_NOPAD.encode(&key.key)}).to_string();

    let keysets = json!({"keysets": [{
        "uuid": KEYSET_UUID,
        "encryptedBy": account_unlock_key.id,
        "sn": 1,
        "encSymKey": seal(account_unlock_key, key_json(&keyset_key).as_bytes()),
        "encPriKey": seal(&keyset_key, include_bytes!("../fixtures/rsa-key.json")),
    }]});
    let account = json!({"vaults": [{
        "uuid": VAULT_UUID,
        "activeItemCount": 1,
        "encAttrs": seal(&vault_key, br#"{"name":"Personal"}"#),
        "access": [{"acl": 32, "encVaultKey": seal(&keyset_key, key_json(&vault_key).as_bytes())}],
    }]});
    let items = json!({
        "contentVersion": 1,
        "batchComplete": true,
        "items": [{
            "uuid": "ITEM",
            "templateUuid": "001",
            "trashed": "N",
            "encOverview": seal(&vault_key, br#"{"title":"Example"}"#),
            "encDetails": seal(&vault_key, b"{}"),
        }],
    });

    (account, keysets, items)
}
