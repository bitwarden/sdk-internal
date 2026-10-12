//! The entry point: log in, unlock the account's keys, download its vaults.

use zeroize::Zeroizing;

use super::{
    account_key::AccountKey,
    credentials::Credentials,
    device::ClientInfo,
    error::OnePasswordError,
    keychain::Keychain,
    login::{self, LoginOutcome},
    model::{
        DownloadedAccount, Item, ItemCategory, SkippedItem, SkippedReason, SkippedVault, Vault,
    },
    opdata::Encrypted,
    rest::RestClient,
    session::Session,
    two_factor::TwoFactorUi,
    wire::{
        AccountInfo, EncryptedEnvelope, KeysetsInfo, VaultAccess, VaultAttributes, VaultItem,
        VaultItemOverview, VaultItemsBatch,
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

    /// Opens the account by signing in and decrypting every accessible vault, driving 2FA through
    /// `ui` when required.
    pub async fn open_account(
        &self,
        credentials: Credentials,
        ui: &dyn TwoFactorUi,
    ) -> Result<DownloadedAccount, OnePasswordError> {
        let mut credentials = Zeroizing::new(credentials);
        credentials.sign_in_address.normalize()?;
        let account_key = AccountKey::parse(&credentials.account_key)?;
        let session = self.login(&credentials, &account_key, ui).await?;
        download_vaults(&credentials, &account_key, &session).await
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
        let device_uuid = super::device::generate_device_uuid();
        let client_info = ClientInfo::for_desktop(&device_uuid);
        let rest = RestClient::new(
            self.http.clone(),
            format!("https://{}/api", credentials.sign_in_address),
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

/// Unlocks the account's keys and downloads every vault the session can open.
pub(super) async fn download_vaults(
    credentials: &Credentials,
    account_key: &AccountKey,
    session: &Session,
) -> Result<DownloadedAccount, OnePasswordError> {
    let (keychain, vaults, mut skipped_vaults) =
        unlock_account(credentials, account_key, session).await?;

    let mut downloaded = Vec::with_capacity(vaults.len());
    for info in vaults {
        match download_vault(info, &keychain, session).await? {
            VaultDownload::Downloaded(vault) => downloaded.push(vault),
            VaultDownload::Skipped(vault) => skipped_vaults.push(vault),
        }
    }

    Ok(DownloadedAccount {
        vaults: downloaded,
        skipped_vaults,
    })
}

/// A vault the account can open, with its attributes already decrypted.
struct VaultInfo {
    id: String,
    name: String,
    item_count: Option<u32>,
}

enum VaultDownload {
    Downloaded(Vault),
    Skipped(SkippedVault),
}

/// Downloads one vault. A missing vault becomes a partial result; every other failure aborts.
async fn download_vault(
    info: VaultInfo,
    keychain: &Keychain,
    session: &Session,
) -> Result<VaultDownload, OnePasswordError> {
    let download = match download_vault_items(&info.id, keychain, session).await {
        Ok(download) => download,
        // TODO: Double check that this is the right error code for a missing vault.
        //       To test that create a shared vault that the user doesn't have access to.
        Err(OnePasswordError::NotFound) => {
            return Ok(VaultDownload::Skipped(SkippedVault {
                id: info.id,
                item_count: info.item_count,
                reason: SkippedReason::NoAccess,
            }));
        }
        Err(error) => return Err(error),
    };

    Ok(VaultDownload::Downloaded(Vault {
        id: info.id,
        name: info.name,
        items: download.items,
        skipped_items: download.skipped_items,
    }))
}

/// Decrypts the account keysets and every accessible vault key.
async fn unlock_account(
    credentials: &Credentials,
    account_key: &AccountKey,
    session: &Session,
) -> Result<(Keychain, Vec<VaultInfo>, Vec<SkippedVault>), OnePasswordError> {
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

    let mut vaults = Vec::new();
    let mut skipped_vaults = Vec::new();
    for vault in &account_info.vaults {
        match unlock_vault(vault, &mut keychain)? {
            VaultUnlock::Unlocked(vault) => vaults.push(vault),
            VaultUnlock::Skipped(vault) => skipped_vaults.push(vault),
        }
    }

    Ok((keychain, vaults, skipped_vaults))
}

enum VaultUnlock {
    Unlocked(VaultInfo),
    Skipped(SkippedVault),
}

/// Decrypts a vault's key and attributes. Missing keys and unsupported encryption are skippable;
/// malformed data is an error.
fn unlock_vault(
    vault: &super::wire::VaultInfo,
    keychain: &mut Keychain,
) -> Result<VaultUnlock, OnePasswordError> {
    let skipped = |reason| {
        VaultUnlock::Skipped(SkippedVault {
            id: vault.uuid.clone(),
            item_count: vault.active_item_count,
            reason,
        })
    };

    let enc_key = match find_working_key(&vault.access, keychain)? {
        VaultKey::Found(enc_key) => enc_key,
        VaultKey::Missing(reason) => return Ok(skipped(reason)),
    };
    keychain.decrypt_aes_key(enc_key)?;

    if let Some(reason) = skip_reason(&vault.enc_attrs, keychain)? {
        return Ok(skipped(reason));
    }
    let attributes: VaultAttributes = keychain.decrypt_json(&vault.enc_attrs)?;
    Ok(VaultUnlock::Unlocked(VaultInfo {
        id: vault.uuid.clone(),
        name: attributes.name.unwrap_or_default(),
        item_count: vault.active_item_count,
    }))
}

struct VaultItemsDownload {
    items: Vec<Item>,
    skipped_items: Vec<SkippedItem>,
}

/// Pages through a vault's items until `batchComplete`, parsing each supported item.
async fn download_vault_items(
    vault_id: &str,
    keychain: &Keychain,
    session: &Session,
) -> Result<VaultItemsDownload, OnePasswordError> {
    let mut items = Vec::new();
    let mut skipped_items = Vec::new();
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
            match parse_item(&item, keychain)? {
                ItemDownload::Downloaded(item) => items.push(item),
                ItemDownload::Skipped(item) => skipped_items.push(item),
            }
        }

        if batch.complete {
            return Ok(VaultItemsDownload {
                items,
                skipped_items,
            });
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

enum ItemDownload {
    Downloaded(Item),
    Skipped(SkippedItem),
}

/// Decrypts both payloads. Missing keys and unsupported encryption are skippable; malformed data
/// is an error.
fn parse_item(item: &VaultItem, keychain: &Keychain) -> Result<ItemDownload, OnePasswordError> {
    let category = ItemCategory::from_template_id(&item.template_uuid);
    if let Some(reason) = skip_reason(&item.enc_overview, keychain)? {
        return Ok(ItemDownload::Skipped(SkippedItem {
            id: item.uuid.clone(),
            name: None,
            category,
            reason,
        }));
    }
    let overview: VaultItemOverview = keychain.decrypt_json(&item.enc_overview)?;

    if let Some(reason) = skip_reason(&item.enc_details, keychain)? {
        return Ok(ItemDownload::Skipped(SkippedItem {
            id: item.uuid.clone(),
            name: overview.title.clone(),
            category,
            reason,
        }));
    }
    let details = keychain.decrypt_json(&item.enc_details)?;

    Ok(ItemDownload::Downloaded(Item {
        id: item.uuid.clone(),
        category,
        overview,
        details,
    }))
}

/// Why `envelope` has to be skipped: its scheme is unsupported or its key is not in the keychain.
/// `None` does not promise it decrypts.
fn skip_reason(
    envelope: &EncryptedEnvelope,
    keychain: &Keychain,
) -> Result<Option<SkippedReason>, OnePasswordError> {
    let encrypted = Encrypted::parse(envelope)?;
    match keychain.can_decrypt(&encrypted) {
        Ok(true) => Ok(None),
        Ok(false) => Ok(Some(SkippedReason::NoAccess)),
        Err(OnePasswordError::Unsupported(_)) => Ok(Some(SkippedReason::Unsupported)),
        Err(error) => Err(error),
    }
}

enum VaultKey<'a> {
    Found(&'a EncryptedEnvelope),
    Missing(SkippedReason),
}

/// Finds a readable access entry whose vault key the keychain can already decrypt.
///
/// Without one, the reason is `Unsupported` when a readable entry uses a scheme we cannot decrypt,
/// otherwise `NoAccess`: a vault the account can see but not open. A malformed envelope is an
/// error.
fn find_working_key<'a>(
    access: &'a [VaultAccess],
    keychain: &Keychain,
) -> Result<VaultKey<'a>, OnePasswordError> {
    let mut reason = SkippedReason::NoAccess;
    for entry in access.iter().filter(|entry| is_read_accessible(entry.acl)) {
        match skip_reason(&entry.enc_vault_key, keychain)? {
            None => return Ok(VaultKey::Found(&entry.enc_vault_key)),
            Some(SkippedReason::Unsupported) => reason = SkippedReason::Unsupported,
            Some(SkippedReason::NoAccess) => {}
        }
    }

    Ok(VaultKey::Missing(reason))
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

        let download = download_vault_items(VAULT_ID, &Keychain::new(), &session(&server))
            .await
            .expect("pagination advances to the final batch");

        assert!(download.items.is_empty());
        assert!(download.skipped_items.is_empty());
        server.verify().await;
    }

    #[tokio::test]
    async fn items_without_keys_are_recorded_and_other_items_continue() {
        let server = MockServer::start().await;
        let readable_key = AesKey::new("VAULT", vec![7u8; 32]);
        let missing_key = AesKey::new("MISSING", vec![8u8; 32]);
        let overview = readable_key
            .encrypt(br#"{"title":"partly readable"}"#, &[1u8; 12])
            .expect("encrypts");
        let missing_overview = missing_key
            .encrypt(br#"{"title":"not readable"}"#, &[2u8; 12])
            .expect("encrypts");
        let missing_details = missing_key.encrypt(br#"{}"#, &[5u8; 12]).expect("encrypts");
        let good_overview = readable_key
            .encrypt(br#"{"title":"readable"}"#, &[3u8; 12])
            .expect("encrypts");
        let good_details = readable_key
            .encrypt(br#"{}"#, &[4u8; 12])
            .expect("encrypts");
        mock_batch(
            &server,
            0,
            json!({
                "contentVersion": 1,
                "batchComplete": true,
                "items": [
                    {
                        "uuid": "bad-details",
                        "templateUuid": "001",
                        "trashed": "N",
                        "encOverview": overview,
                        "encDetails": missing_details
                    },
                    {
                        "uuid": "bad-overview",
                        "templateUuid": "002",
                        "trashed": "N",
                        "encOverview": missing_overview,
                        "encDetails": {
                            "kid": "VAULT", "enc": "A256GCM", "cty": "b5+jwk+json",
                            "data": "!"
                        }
                    },
                    {
                        "uuid": "good-item",
                        "templateUuid": "003",
                        "trashed": "N",
                        "encOverview": good_overview,
                        "encDetails": good_details
                    },
                    {
                        "uuid": "unsupported-encryption",
                        "templateUuid": "004",
                        "trashed": "N",
                        "encOverview": {
                            "kid": "VAULT", "enc": "FUTURE", "cty": "b5+jwk+json", "data": ""
                        },
                        "encDetails": {
                            "kid": "VAULT", "enc": "A256GCM", "cty": "b5+jwk+json", "data": ""
                        }
                    }
                ]
            }),
        )
        .await;

        let mut keychain = Keychain::new();
        keychain.add_aes(readable_key);
        let download = download_vault_items(VAULT_ID, &keychain, &session(&server))
            .await
            .expect("one bad item does not fail its vault");

        assert_eq!(download.items.len(), 1);
        assert_eq!(download.items[0].id, "good-item");
        assert_eq!(download.skipped_items.len(), 3);
        assert_eq!(download.skipped_items[0].id, "bad-details");
        assert_eq!(
            download.skipped_items[0].name.as_deref(),
            Some("partly readable")
        );
        assert_eq!(download.skipped_items[0].category, ItemCategory::Login);
        assert_eq!(download.skipped_items[0].reason, SkippedReason::NoAccess);
        assert_eq!(download.skipped_items[1].id, "bad-overview");
        assert_eq!(download.skipped_items[1].name, None);
        assert_eq!(download.skipped_items[1].category, ItemCategory::CreditCard);
        assert_eq!(download.skipped_items[1].reason, SkippedReason::NoAccess);
        assert_eq!(download.skipped_items[2].id, "unsupported-encryption");
        assert_eq!(download.skipped_items[2].reason, SkippedReason::Unsupported);
        server.verify().await;
    }

    #[test]
    fn invalid_json_or_undecryptable_items_are_errors() {
        let readable_key = AesKey::new("VAULT", vec![7u8; 32]);
        let wrong_key = AesKey::new("VAULT", vec![8u8; 32]);
        let details = readable_key
            .encrypt(br#"{}"#, &[1u8; 12])
            .expect("encrypts");
        let invalid_json: VaultItem = serde_json::from_value(json!({
            "uuid": "invalid-json",
            "templateUuid": "001",
            "trashed": "N",
            "encOverview": readable_key
                .encrypt(b"not json", &[4u8; 12])
                .expect("encrypts"),
            "encDetails": details,
        }))
        .expect("valid item envelope");
        let undecryptable: VaultItem = serde_json::from_value(json!({
            "uuid": "undecryptable",
            "templateUuid": "001",
            "trashed": "N",
            "encOverview": wrong_key
                .encrypt(br#"{}"#, &[2u8; 12])
                .expect("encrypts"),
            "encDetails": readable_key
                .encrypt(br#"{}"#, &[3u8; 12])
                .expect("encrypts"),
        }))
        .expect("valid item envelope");

        let mut keychain = Keychain::new();
        keychain.add_aes(readable_key);
        assert!(matches!(
            parse_item(&invalid_json, &keychain),
            Err(OnePasswordError::Parse)
        ));
        assert!(matches!(
            parse_item(&undecryptable, &keychain),
            Err(OnePasswordError::Internal(_))
        ));
    }

    #[tokio::test]
    async fn download_stops_when_pagination_does_not_advance() {
        let server = MockServer::start().await;
        mock_batch(&server, 0, batch(7, false)).await;
        mock_batch(&server, 7, batch(7, false)).await;

        let error = download_vault_items(VAULT_ID, &Keychain::new(), &session(&server))
            .await
            .map(|_| ())
            .expect_err("refetching the same page is an error, not a loop");

        assert!(
            error.to_string().contains("pagination stalled"),
            "unexpected error: {error}"
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn a_missing_vault_is_reported() {
        let server = MockServer::start().await;
        server
            .register(
                Mock::given(matchers::path(format!("/api/v1/vault/{VAULT_ID}/0/items")))
                    .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                        "errorCode": 117,
                        "errorMessage": "vault not found",
                    })))
                    .expect(1),
            )
            .await;

        let result = download_vault(
            VaultInfo {
                id: VAULT_ID.into(),
                name: "Known vault".into(),
                item_count: Some(17),
            },
            &Keychain::new(),
            &session(&server),
        )
        .await
        .expect("a missing vault only skips that vault");

        let VaultDownload::Skipped(vault) = result else {
            panic!("the failed vault should be reported as skipped");
        };
        assert_eq!(vault.id, VAULT_ID);
        assert_eq!(vault.item_count, Some(17));
        assert_eq!(vault.reason, SkippedReason::NoAccess);
        server.verify().await;
    }

    #[tokio::test]
    async fn an_auth_or_transient_vault_failure_aborts_the_import() {
        for status in [401, 503] {
            let server = MockServer::start().await;
            server
                .register(
                    Mock::given(matchers::path(format!("/api/v1/vault/{VAULT_ID}/0/items")))
                        .respond_with(ResponseTemplate::new(status))
                        .expect(1),
                )
                .await;

            let result = download_vault(
                VaultInfo {
                    id: VAULT_ID.into(),
                    name: "Known vault".into(),
                    item_count: Some(17),
                },
                &Keychain::new(),
                &session(&server),
            )
            .await;

            assert!(result.is_err());
            server.verify().await;
        }
    }

    fn access(acl: i32, kid: &str) -> VaultAccess {
        access_with_scheme(acl, kid, "A256GCM")
    }

    fn access_with_scheme(acl: i32, kid: &str, scheme: &str) -> VaultAccess {
        serde_json::from_value(json!({
            "acl": acl,
            "encVaultKey": {"kid": kid, "enc": scheme, "cty": "b5+jwk+json", "data": ""},
        }))
        .expect("valid access entry")
    }

    #[test]
    fn a_vault_with_unreadable_attributes_is_skipped() {
        let account_key = AesKey::new("ACCOUNT", vec![1u8; 32]);
        let vault_key = json!({"kid": "VAULT", "k": "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM"});
        let enc_vault_key = account_key
            .encrypt(vault_key.to_string().as_bytes(), &[0u8; 12])
            .expect("encrypts");
        let mut keychain = Keychain::new();
        keychain.add_aes(account_key);

        for (kid, scheme, expected) in [
            ("VAULT", "FUTURE", SkippedReason::Unsupported),
            ("MISSING", "A256GCM", SkippedReason::NoAccess),
        ] {
            let vault: super::super::wire::VaultInfo = serde_json::from_value(json!({
                "uuid": VAULT_ID,
                "encAttrs": {"kid": kid, "enc": scheme, "cty": "b5+jwk+json", "data": ""},
                "access": [{"acl": 32, "encVaultKey": enc_vault_key}],
            }))
            .expect("valid vault");

            let unlocked =
                unlock_vault(&vault, &mut keychain).expect("the envelopes are well formed");
            assert!(matches!(
                unlocked,
                VaultUnlock::Skipped(SkippedVault { reason, .. }) if reason == expected
            ));
        }
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
            // Readable, but in a scheme we cannot decrypt.
            access_with_scheme(32, "usable", "FUTURE"),
            // The key is in the keychain, but there is no read access.
            access(1, "usable"),
            // Both.
            access(32, "usable"),
        ];

        let found = find_working_key(&entries, &keychain).expect("the envelopes are well formed");
        assert!(matches!(
            found,
            VaultKey::Found(entry) if entry.kid == "usable" && entry.enc == "A256GCM"
        ));
    }

    #[test]
    fn find_working_key_reports_no_access_without_a_usable_entry() {
        let keychain = Keychain::new();
        let entries = [
            access(32, "missing"),
            // Without read access the scheme does not matter.
            access_with_scheme(1, "missing", "FUTURE"),
        ];

        let found = find_working_key(&entries, &keychain).expect("the envelopes are well formed");
        assert!(matches!(found, VaultKey::Missing(SkippedReason::NoAccess)));
    }

    #[test]
    fn find_working_key_reports_an_unsupported_scheme() {
        let keychain = Keychain::new();
        let entries = [
            access_with_scheme(32, "missing", "FUTURE"),
            access(32, "missing"),
        ];

        let found = find_working_key(&entries, &keychain).expect("the envelopes are well formed");
        assert!(matches!(
            found,
            VaultKey::Missing(SkippedReason::Unsupported)
        ));
    }
}
