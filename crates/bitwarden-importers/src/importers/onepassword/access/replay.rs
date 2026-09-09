//! Replays a captured 1Password account through the production download path.
//!
//! The fixtures are the session-decrypted response bodies exactly as the server sent them: the
//! per-item `encOverview` and `encDetails` are still sealed with the vault key. Re-encrypting them
//! with a known session key and serving them from a mock host means the real client does the
//! decrypting and parsing, so these tests exercise production code rather than a parallel loader.
//!
//! The account is a disposable one kept for exactly this purpose, so its credentials live here.

use bitwarden_api_base::new_http_client;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

use super::{
    account_key::AccountKey,
    client::download_vaults,
    credentials::Credentials,
    model::Vault,
    opdata::{AesKey, decode64_loose},
    rest::RestClient,
    session::Session,
    sign_in::{SignInAddress, SignInDomain},
};

const USERNAME: &str = "lastpass.ruby+01-april-2026@gmail.com";
const PASSWORD: &str = "what's a password?";
const ACCOUNT_KEY: &str = "A3-9RVQ2J-EJMXAS-KHSXJ-6M9PJ-3W8WD-E4DRY";

/// The vaults the capture covers, paired with their items response.
const VAULTS: [(&str, &str); 2] = [
    (
        "wv2hn4jgomxwvfh4oiubyjppym",
        include_str!("../fixtures/vault-wv2hn4jgomxwvfh4oiubyjppym-items-response.json"),
    ),
    (
        "d7z3byaorasfq5xixos3tgaddu",
        include_str!("../fixtures/vault-d7z3byaorasfq5xixos3tgaddu-items-response.json"),
    ),
];

/// Any key works: the fixtures are re-encrypted with it here, then decrypted by the client.
fn session_key() -> AesKey {
    AesKey::new(
        "SESSION",
        decode64_loose("WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM").expect("valid key"),
    )
}

fn credentials() -> Credentials {
    Credentials {
        username: USERNAME.to_string(),
        password: PASSWORD.to_string(),
        account_key: ACCOUNT_KEY.to_string(),
        sign_in_address: SignInAddress::new("my", SignInDomain::Global).expect("valid address"),
        device_uuid: "replay-device".to_string(),
    }
}

/// Serves `body` from `path`, wrapped in an opdata envelope the session key opens.
async fn mock_encrypted(server: &MockServer, path: String, body: &str) {
    let envelope = session_key()
        .encrypt(body.as_bytes(), &[0u8; 12])
        .expect("encrypts");
    server
        .register(
            Mock::given(matchers::path(path)).respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::to_value(&envelope).expect("serializes")),
            ),
        )
        .await;
}

/// Downloads the captured account the same way an import does, minus the login exchange.
pub(in crate::importers::onepassword) async fn download_captured_account() -> Vec<Vault> {
    let server = MockServer::start().await;
    mock_encrypted(
        &server,
        "/api/v1/account".to_string(),
        include_str!("../fixtures/account-response.json"),
    )
    .await;
    mock_encrypted(
        &server,
        "/api/v1/account/keysets".to_string(),
        include_str!("../fixtures/keysets-response.json"),
    )
    .await;
    for (vault_id, items) in VAULTS {
        mock_encrypted(&server, format!("/api/v1/vault/{vault_id}/0/items"), items).await;
    }

    let rest = RestClient::new(
        new_http_client(),
        format!("http://{}/api", server.address()),
        "client-id",
        "user-agent",
        "op-user-agent",
    )
    .expect("valid headers");

    let credentials = credentials();
    let account_key = AccountKey::parse(&credentials.account_key).expect("valid account key");
    let session = Session::new(session_key(), rest);

    download_vaults(&credentials, &account_key, &session)
        .await
        .expect("the captured responses decrypt and parse")
}
