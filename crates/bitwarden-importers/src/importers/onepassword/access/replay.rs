//! Replays a captured 1Password account through the production download path.
//!
//! The fixtures are the session-decrypted response bodies exactly as the server sent them: the
//! per-item `encOverview` and `encDetails` are still sealed with the vault key. Re-encrypting them
//! with a known session key and serving them from a mock host means the real client does the
//! decrypting and parsing, so these tests exercise production code rather than a parallel loader.
//!
//! The capture came from a disposable account. `fixtures/scripts/reencrypt.mjs` then re-sealed its
//! master keyset under the made-up credentials below, so nothing here opens a real account.

use bitwarden_api_base::new_http_client;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

use super::{
    account_key::AccountKey,
    client::download_vaults,
    credentials::Credentials,
    model::DownloadedAccount,
    opdata::{AesKey, decode64_loose},
    rest::RestClient,
    session::Session,
    sign_in::{SignInAddress, SignInDomain},
};

const USERNAME: &str = "user@example.com";
const PASSWORD: &str = "password";
const ACCOUNT_KEY: &str = "A3-ABCDEF-GHJKLM-NPQRS-TVWXY-Z2345-6789A";

/// The vaults the capture covers, paired with their items response.
const VAULTS: [(&str, &str); 2] = [
    (
        "wv2hn4jgomxwvfh4oiubyjppym",
        include_str!("fixtures/account/vault-wv2hn4jgomxwvfh4oiubyjppym-items-response.json"),
    ),
    (
        "d7z3byaorasfq5xixos3tgaddu",
        include_str!("fixtures/account/vault-d7z3byaorasfq5xixos3tgaddu-items-response.json"),
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
        sign_in_address: SignInAddress {
            subdomain: "my".into(),
            domain: SignInDomain::Global,
        },
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
pub(in crate::importers::onepassword) async fn download_captured_account() -> DownloadedAccount {
    download_account_fixture(include_str!("fixtures/account/account-response.json")).await
}

async fn download_account_fixture(account_response: &str) -> DownloadedAccount {
    let server = MockServer::start().await;
    mock_encrypted(&server, "/api/v1/account".to_string(), account_response).await;
    mock_encrypted(
        &server,
        "/api/v1/account/keysets".to_string(),
        include_str!("fixtures/account/keysets-response.json"),
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

#[tokio::test]
async fn an_inaccessible_vault_keeps_its_available_metadata() {
    let mut response: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/account/account-response.json"))
            .expect("valid account response");
    let vault = &mut response["vaults"][0];
    for access in vault["access"].as_array_mut().expect("vault access list") {
        access["encVaultKey"]["kid"] = "a-key-the-account-does-not-have".into();
    }

    let account = download_account_fixture(&response.to_string()).await;

    assert_eq!(account.vaults.len(), 1);
    assert_eq!(account.skipped_vaults.len(), 1);
    let skipped = &account.skipped_vaults[0];
    assert_eq!(skipped.id, "wv2hn4jgomxwvfh4oiubyjppym");
    assert_eq!(skipped.item_count, Some(1));
    assert_eq!(skipped.reason, super::model::SkippedReason::NoAccess);
}
