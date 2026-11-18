use bitwarden_collections::collection::Collection;
use bitwarden_core::{
    Client, NotAuthenticatedError, OrganizationId, UserId, key_management::KeySlotIds,
};
use bitwarden_crypto::{CompositeEncryptable, IdentifyKey, KeyStoreContext};
use bitwarden_vault::{
    Cipher, CipherView, EncryptMode, EncryptionContext, Folder, FolderView,
    should_use_blob_encryption,
};

use crate::{
    ExportError, ExportFormat, ImportingCipher,
    csv::export_csv,
    cxf::{Account, build_cxf, parse_cxf},
    encrypted_json::export_encrypted_json,
    json::export_json,
};

pub(crate) async fn export_vault(
    client: &Client,
    folders: Vec<Folder>,
    ciphers: Vec<Cipher>,
    format: ExportFormat,
) -> Result<String, ExportError> {
    let key_store = client.internal.get_key_store();

    let folders: Vec<FolderView> = key_store.decrypt_list(&folders)?;
    let folders: Vec<crate::Folder> = folders.into_iter().flat_map(|f| f.try_into()).collect();

    let ciphers: Vec<crate::Cipher> = ciphers
        .into_iter()
        .flat_map(|c| crate::Cipher::from_cipher(key_store, c))
        .collect();

    match format {
        ExportFormat::Csv => Ok(export_csv(folders, ciphers)?),
        ExportFormat::Json => Ok(export_json(folders, ciphers)?),
        ExportFormat::EncryptedJson { password } => Ok(export_encrypted_json(
            folders,
            ciphers,
            password,
            client.internal.get_kdf().await?,
        )?),
    }
}

pub(crate) fn export_organization_vault(
    _collections: Vec<Collection>,
    _ciphers: Vec<Cipher>,
    _format: ExportFormat,
) -> Result<String, ExportError> {
    todo!();
}

/// See [crate::ExporterClient::export_cxf] for more documentation.
pub(crate) fn export_cxf(
    client: &Client,
    account: Account,
    ciphers: Vec<Cipher>,
) -> Result<String, ExportError> {
    let key_store = client.internal.get_key_store();

    let mut ciphers: Vec<crate::Cipher> = ciphers
        .into_iter()
        .flat_map(|c| crate::Cipher::from_cipher(key_store, c))
        .collect();

    for cipher in &mut ciphers {
        if let crate::CipherType::Login(login) = &mut cipher.r#type {
            login.sanitize_uris();
        }
    }

    Ok(build_cxf(account, ciphers)?)
}

/// Encrypts a parsed/imported cipher for the user's vault, or for an organization when
/// `organization_id` is set. Shared by the importers (`import_kdbx`) and by CXF import; lives here
/// alongside the `ImportingCipher` interchange model and the `From<ImportingCipher> for CipherView`
/// bridge.
///
/// `user_id` identifies the user performing the import and is recorded on the returned
/// [`EncryptionContext`] alongside the id of the key the cipher was wrapped under.
pub fn encrypt_import(
    ctx: &mut KeyStoreContext<KeySlotIds>,
    cipher: ImportingCipher,
    organization_id: Option<OrganizationId>,
    user_id: UserId,
) -> Result<EncryptionContext, ExportError> {
    let mut view: CipherView = cipher.clone().into();
    view.organization_id = organization_id;

    // Get passkey from cipher if cipher is type login
    let passkey = match cipher.r#type {
        crate::CipherType::Login(login) => login.fido2_credentials,
        _ => None,
    };

    if let Some(passkey) = passkey {
        let passkeys = passkey.into_iter().map(|p| p.into()).collect();

        view.set_new_fido2_credentials(ctx, passkeys)?;
    }

    // Capture the id of the wrapping key - the organization key for org-owned ciphers, the user key
    // otherwise - before encrypting, since that borrows the context mutably.
    let key = view.key_identifier();
    let encrypted_by_key_id = ctx.get_symmetric_key_id(key).map(|id| id.to_string());

    // Select the encryption format based on the account's current security state, matching how
    // regular cipher saves choose between the blob and legacy field-level formats.
    let mode = if should_use_blob_encryption(ctx, organization_id) {
        EncryptMode::Blob(view)
    } else {
        EncryptMode::Legacy(view)
    };
    let new_cipher = mode.encrypt_composite(ctx, key)?;

    Ok(EncryptionContext {
        cipher: new_cipher,
        encrypted_for: user_id,
        encrypted_by_key_id,
    })
}

/// See [crate::ExporterClient::import_cxf] for more documentation.
pub(crate) fn import_cxf(
    client: &Client,
    payload: String,
) -> Result<Vec<EncryptionContext>, ExportError> {
    let user_id = client.internal.get_user_id().ok_or(NotAuthenticatedError)?;

    let key_store = client.internal.get_key_store();
    let mut ctx = key_store.context();

    let ciphers = parse_cxf(payload)?;
    let ciphers: Result<Vec<EncryptionContext>, _> = ciphers
        .into_iter()
        .map(|c| encrypt_import(&mut ctx, c, None, user_id))
        .collect();

    ciphers
}

#[cfg(test)]
mod tests {
    use bitwarden_core::{
        client::test_accounts::{test_bitwarden_com_account, test_bitwarden_com_account_v2},
        key_management::SymmetricKeySlotId,
    };

    use super::*;

    fn dashlane_payload() -> String {
        std::fs::read_to_string("resources/dashlane_export.json").unwrap()
    }

    /// The imported ciphers are attributed to the importing user and are actually encrypted.
    #[tokio::test]
    async fn import_cxf_returns_encryption_context() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let user_id = client.internal.get_user_id().unwrap();

        let imported = import_cxf(&client, dashlane_payload()).unwrap();

        assert!(!imported.is_empty());
        assert!(imported.iter().all(|c| c.encrypted_for == user_id));

        // "adobe.com" is one of the plaintext titles in the fixture; it must not survive as-is.
        let names: Vec<String> = imported
            .iter()
            .map(|c| c.cipher.name.as_ref().unwrap().to_string())
            .collect();
        assert!(!names.iter().any(|n| n == "adobe.com"));
    }

    /// The user key's id is recorded so the server can reject writes made under a stale key. Both
    /// the V1 (AES-CBC-HMAC) and V2 (XAES-256-GCM) user keys carry one.
    #[tokio::test]
    async fn import_cxf_records_user_key_id() {
        for account in [
            test_bitwarden_com_account(),
            test_bitwarden_com_account_v2(),
        ] {
            let client = Client::init_test_account(account).await;
            let expected = client
                .internal
                .get_key_store()
                .context()
                .get_symmetric_key_id(SymmetricKeySlotId::User)
                .map(|id| id.to_string());
            assert!(expected.is_some());

            let imported = import_cxf(&client, dashlane_payload()).unwrap();

            assert!(!imported.is_empty());
            for context in &imported {
                assert_eq!(context.encrypted_by_key_id, expected);
            }
        }
    }
}
