use bitwarden_collections::collection::Collection;
use bitwarden_core::{Client, key_management::KeySlotIds};
use bitwarden_crypto::{CompositeEncryptable, IdentifyKey, KeyStoreContext};
use bitwarden_vault::{Cipher, CipherView, Folder, FolderView};
use zeroize::Zeroizing;

use crate::{
    ExportError, ExportFormat, FolderRelationship, ImportingCipher, KdbxImportResult,
    csv::export_csv,
    cxf::{Account, build_cxf, parse_cxf},
    encrypted_json::export_encrypted_json,
    json::export_json,
    kdbx::parse_kdbx,
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

fn encrypt_import(
    ctx: &mut KeyStoreContext<KeySlotIds>,
    cipher: ImportingCipher,
) -> Result<Cipher, ExportError> {
    let mut view: CipherView = cipher.clone().into();

    // Get passkey from cipher if cipher is type login
    let passkey = match cipher.r#type {
        crate::CipherType::Login(login) => login.fido2_credentials,
        _ => None,
    };

    if let Some(passkey) = passkey {
        let passkeys = passkey.into_iter().map(|p| p.into()).collect();

        view.set_new_fido2_credentials(ctx, passkeys)?;
    }

    let new_cipher = view.encrypt_composite(ctx, view.key_identifier())?;

    Ok(new_cipher)
}

/// See [crate::ExporterClient::import_cxf] for more documentation.
pub(crate) fn import_cxf(client: &Client, payload: String) -> Result<Vec<Cipher>, ExportError> {
    let key_store = client.internal.get_key_store();
    let mut ctx = key_store.context();

    let ciphers = parse_cxf(payload)?;
    let ciphers: Result<Vec<Cipher>, _> = ciphers
        .into_iter()
        .map(|c| encrypt_import(&mut ctx, c))
        .collect();

    ciphers
}

/// See [crate::ExporterClient::import_kdbx] for more documentation.
pub(crate) fn import_kdbx(
    client: &Client,
    file: Vec<u8>,
    password: Option<String>,
    key_file: Option<Vec<u8>>,
) -> Result<KdbxImportResult, ExportError> {
    let file = Zeroizing::new(file);
    let password = password.map(Zeroizing::new);
    let key_file = key_file.map(Zeroizing::new);

    let parsed = parse_kdbx(
        &file,
        password.as_ref().map(|p| p.as_str()),
        key_file.as_ref().map(|k| k.as_slice()),
    )?;

    let key_store = client.internal.get_key_store();
    let mut ctx = key_store.context();

    let ciphers = parsed
        .ciphers
        .into_iter()
        .map(|c| encrypt_import(&mut ctx, c))
        .collect::<Result<Vec<Cipher>, _>>()?;

    let folders = parsed
        .folders
        .into_iter()
        .map(|name| encrypt_folder(&mut ctx, name))
        .collect::<Result<Vec<Folder>, _>>()?;

    let folder_relationships = parsed
        .folder_relationships
        .into_iter()
        .map(|(cipher, folder)| FolderRelationship {
            cipher: cipher as u32,
            folder: folder as u32,
        })
        .collect();

    Ok(KdbxImportResult {
        ciphers,
        folders,
        folder_relationships,
    })
}

fn encrypt_folder(
    ctx: &mut KeyStoreContext<KeySlotIds>,
    name: String,
) -> Result<Folder, ExportError> {
    let view = FolderView {
        id: None,
        name,
        revision_date: chrono::Utc::now(),
    };
    Ok(view.encrypt_composite(ctx, view.key_identifier())?)
}
