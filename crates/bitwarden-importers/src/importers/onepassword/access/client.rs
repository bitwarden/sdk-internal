//! The entry point: log in, unlock the account's keys, download its vaults.

use super::{
    account_key::AccountKey,
    credentials::Credentials,
    device::ClientInfo,
    error::OnePasswordError,
    keychain::Keychain,
    login::{self, LoginOutcome},
    model::{Item, ItemCategory, Vault},
    opdata::Encrypted,
    rest::RestClient,
    session::Session,
    two_factor::TwoFactorUi,
    wire::{
        AccountInfo, EncryptedEnvelope, KeysetsInfo, VaultAccess, VaultAttributes, VaultItem,
        VaultItemDetails, VaultItemOverview, VaultItemsBatch,
    },
};

const PASSWORD_SK_METHOD: &str = "PASSWORD+SK";
const MAX_OTP_ATTEMPTS: u32 = 3;
const ACCOUNT_INFO_ENDPOINT: &str =
    "v1/account?attrs=billing,counts,groups,invite,me,settings,tier,user-flags,users,vaults";
const KEYSETS_ENDPOINT: &str = "v1/account/keysets";
const VAULT_ENDPOINT: &str = "v1/vault";

/// The 1Password client. Holds the injected HTTP transport so tests can point it at a mock host.
pub struct Client {
    http: reqwest::Client,
}

impl Client {
    /// Creates a client over the given HTTP transport. The caller owns TLS configuration; in the
    /// SDK that means `bitwarden_api_base::new_http_client()` or the client's own pooled instance.
    pub fn new(http: reqwest::Client) -> Client {
        Client { http }
    }

    /// Logs in and downloads every vault the account can open, driving 2FA through `ui` when
    /// required.
    ///
    /// An import takes the whole account, so there is no vault selection.
    pub async fn download_all_vaults(
        &self,
        credentials: &Credentials,
        ui: &dyn TwoFactorUi,
    ) -> Result<Vec<Vault>, OnePasswordError> {
        let account_key = AccountKey::parse(&credentials.account_key)?;
        let session = self.login(credentials, &account_key, ui).await?;
        let (keychain, vaults) = unlock(credentials, &account_key, &session).await?;

        let mut downloaded = Vec::with_capacity(vaults.len());
        for info in &vaults {
            downloaded.push(Vault {
                id: info.id.clone(),
                name: info.name.clone(),
                description: info.description.clone(),
                items: download_vault_items(&info.id, &keychain, &session).await?,
            });
        }

        Ok(downloaded)
    }

    /// Runs the login sequence, retrying the whole thing when the server rejects a TOTP code.
    ///
    /// A rejected code makes 1Password invalidate the session, so a wrong code restarts from
    /// scratch, up to three times.
    async fn login(
        &self,
        credentials: &Credentials,
        account_key: &AccountKey,
        ui: &dyn TwoFactorUi,
    ) -> Result<Session, OnePasswordError> {
        let client_info = ClientInfo::for_desktop(&credentials.device_uuid);
        let rest = RestClient::new(
            self.http.clone(),
            format!("https://{}/api", credentials.domain),
            &client_info.client_id(),
            &client_info.user_agent,
            &client_info.op_user_agent,
        )?;

        // Confirm password + Secret Key login is available. This does not change between attempts.
        let login_info = login::fetch_auth_methods(&credentials.username, &rest).await?;
        if !login_info
            .auth_methods
            .iter()
            .any(|m| m.kind == PASSWORD_SK_METHOD)
        {
            return Err(OnePasswordError::Unsupported(format!(
                "no password login method found for account {}",
                credentials.username
            )));
        }

        for attempt in 0..MAX_OTP_ATTEMPTS {
            match login::login_attempt(credentials, account_key, &client_info, attempt, ui, &rest)
                .await?
            {
                LoginOutcome::Success(session) => return Ok(*session),
                LoginOutcome::BadOtp => continue,
            }
        }

        Err(OnePasswordError::TwoFactorFailed)
    }
}

/// A vault the account can open, with its attributes already decrypted.
struct VaultInfo {
    id: String,
    name: String,
    description: String,
}

/// Decrypts the account keysets and every accessible vault key.
///
/// The keychain is complete when this returns, so the download itself never adds to it.
async fn unlock(
    credentials: &Credentials,
    account_key: &AccountKey,
    session: &Session,
) -> Result<(Keychain, Vec<VaultInfo>), OnePasswordError> {
    // The vault list, and the keysets that unlock it.
    let account_info: AccountInfo = session
        .rest
        .get_encrypted_json(ACCOUNT_INFO_ENDPOINT, &session.key)
        .await?;
    let keysets: KeysetsInfo = session
        .rest
        .get_encrypted_json(KEYSETS_ENDPOINT, &session.key)
        .await?;

    // Everything else hangs off the master key, which only the credentials can produce.
    let mut keychain = Keychain::new();
    keychain.decrypt_keysets(
        &keysets.keysets,
        &credentials.username,
        &credentials.password,
        account_key,
    )?;

    // A vault whose key we do not hold is one the account can see but not open.
    // TODO: Report skipped vaults and failed items instead of dropping them silently or failing the
    // entire import.
    let mut vaults = Vec::new();
    for vault in &account_info.vaults {
        let Some(enc_key) = find_working_key(&vault.access, &keychain)? else {
            continue;
        };
        keychain.decrypt_aes_key(enc_key)?;

        let attributes: VaultAttributes = keychain.decrypt_json(&vault.enc_attrs)?;
        vaults.push(VaultInfo {
            id: vault.uuid.clone(),
            name: attributes.name.unwrap_or_default(),
            description: attributes.desc.unwrap_or_default(),
        });
    }

    Ok((keychain, vaults))
}

/// Pages through a vault's items until `batchComplete`, parsing each supported item.
async fn download_vault_items(
    vault_id: &str,
    keychain: &Keychain,
    session: &Session,
) -> Result<Vec<Item>, OnePasswordError> {
    let mut items = Vec::new();
    let mut batch_id: i64 = 0;
    loop {
        let batch: VaultItemsBatch = session
            .rest
            .get_encrypted_json(
                &format!("{VAULT_ENDPOINT}/{vault_id}/{batch_id}/items"),
                &session.key,
            )
            .await?;

        for item in batch.items.into_iter().flatten() {
            if item.trashed == "Y" {
                continue;
            }
            items.push(parse_item(&item, keychain)?);
        }

        if batch.complete {
            return Ok(items);
        }

        // The batch id is a cursor, so an unchanged (or rewound) version would refetch the same
        // page forever and duplicate its items. Nothing can make progress from here.
        if batch.version <= batch_id {
            return Err(OnePasswordError::Internal(format!(
                "vault {vault_id} pagination stalled at content version {batch_id}"
            )));
        }
        batch_id = batch.version;
    }
}

/// Decrypts both payloads. Every category is kept, not only logins.
fn parse_item(item: &VaultItem, keychain: &Keychain) -> Result<Item, OnePasswordError> {
    Ok(Item {
        id: item.uuid.clone(),
        category: ItemCategory::from_template_id(&item.template_uuid),
        overview: keychain.decrypt_json(&item.enc_overview)?,
        details: keychain.decrypt_json(&item.enc_details)?,
    })
}

/// Finds a readable access entry whose vault key the keychain can already decrypt.
///
/// `None` means every readable entry names a key we do not hold, which is a vault the account can
/// see but not open. A malformed envelope or an unsupported scheme is an error instead, so an
/// unreadable format never passes for a missing key.
fn find_working_key<'a>(
    access: &'a [VaultAccess],
    keychain: &Keychain,
) -> Result<Option<&'a EncryptedEnvelope>, OnePasswordError> {
    for entry in access {
        if is_read_accessible(entry.acl) {
            let encrypted = Encrypted::parse(&entry.enc_vault_key)?;
            if keychain.can_decrypt(&encrypted)? {
                return Ok(Some(&entry.enc_vault_key));
            }
        }
    }

    Ok(None)
}

/// Whether an ACL grants read access.
fn is_read_accessible(acl: i32) -> bool {
    const HAVE_READ_ACCESS: i32 = 32;
    acl & HAVE_READ_ACCESS != 0
}

#[cfg(test)]
mod tests {
    use bitwarden_api_base::new_http_client;
    use serde_json::json;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

    use super::{
        super::opdata::{AesKey, decode64_loose},
        *,
    };

    const VAULT_ID: &str = "vault-id";

    fn session(server: &MockServer) -> Session {
        let rest = RestClient::new(
            new_http_client(),
            format!("http://{}/api", server.address()),
            "client-id",
            "user-agent",
            "op-user-agent",
        )
        .expect("valid headers");

        Session::new(session_key(), rest)
    }

    fn session_key() -> AesKey {
        AesKey::new(
            "SESSION",
            decode64_loose("WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM").expect("valid key"),
        )
    }

    /// Registers an encrypted items batch at `v1/vault/{VAULT_ID}/{batch_id}/items`.
    async fn mock_batch(server: &MockServer, batch_id: i64, body: serde_json::Value) {
        let envelope = session_key()
            .encrypt(body.to_string().as_bytes(), &[0u8; 12])
            .expect("encrypts");
        server
            .register(
                Mock::given(matchers::path(format!(
                    "/api/v1/vault/{VAULT_ID}/{batch_id}/items"
                )))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::to_value(&envelope).expect("serializes")),
                )
                .expect(1),
            )
            .await;
    }

    fn batch(version: i64, complete: bool) -> serde_json::Value {
        json!({"contentVersion": version, "batchComplete": complete, "items": []})
    }

    #[tokio::test]
    async fn download_pages_until_the_batch_is_complete() {
        let server = MockServer::start().await;
        mock_batch(&server, 0, batch(7, false)).await;
        mock_batch(&server, 7, batch(9, true)).await;

        let items = download_vault_items(VAULT_ID, &Keychain::new(), &session(&server))
            .await
            .expect("pagination advances to the final batch");

        assert!(items.is_empty());
        server.verify().await;
    }

    #[tokio::test]
    async fn download_stops_when_pagination_does_not_advance() {
        let server = MockServer::start().await;
        mock_batch(&server, 0, batch(7, false)).await;
        mock_batch(&server, 7, batch(7, false)).await;

        let error = download_vault_items(VAULT_ID, &Keychain::new(), &session(&server))
            .await
            .expect_err("refetching the same page is an error, not a loop");

        assert!(
            error.to_string().contains("pagination stalled"),
            "unexpected error: {error}"
        );
        server.verify().await;
    }

    fn access(acl: i32, kid: &str) -> VaultAccess {
        serde_json::from_value(json!({
            "acl": acl,
            "encVaultKey": {"kid": kid, "enc": "A256GCM", "cty": "b5+jwk+json", "data": ""},
        }))
        .expect("valid access entry")
    }

    #[test]
    fn read_access_requires_the_read_bit() {
        assert!(is_read_accessible(32));
        assert!(is_read_accessible(0xFFFF));
        assert!(!is_read_accessible(0));
        assert!(!is_read_accessible(31));
    }

    #[test]
    fn find_working_key_skips_entries_we_cannot_use() {
        let mut keychain = Keychain::new();
        keychain.add_aes(AesKey::new("usable", vec![0u8; 32]));

        let entries = vec![
            // Readable, but the key is not in the keychain.
            access(32, "missing"),
            // The key is in the keychain, but there is no read access.
            access(1, "usable"),
            // Both.
            access(32, "usable"),
        ];

        let found = find_working_key(&entries, &keychain)
            .expect("the schemes are all supported")
            .expect("a usable entry");
        assert_eq!(found.kid, "usable");
    }

    #[test]
    fn find_working_key_returns_nothing_without_a_usable_entry() {
        let keychain = Keychain::new();
        let entries = [access(32, "missing")];
        let found = find_working_key(&entries, &keychain).expect("the scheme is supported");
        assert!(found.is_none());
    }
}
