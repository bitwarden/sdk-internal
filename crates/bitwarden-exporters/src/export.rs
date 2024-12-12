use bitwarden_core::Client;
use bitwarden_crypto::{KeyContainer, KeyDecryptable, KeyEncryptable, LocateKey};
use bitwarden_vault::{Cipher, CipherView, Collection, Folder, FolderView};

use crate::{
    csv::export_csv,
    cxp::{build_cxf, parse_cxf, Account},
    encrypted_json::export_encrypted_json,
    json::export_json,
    ExportError, ExportFormat, ImportingCipher,
};

pub(crate) fn export_vault(
    client: &Client,
    folders: Vec<Folder>,
    ciphers: Vec<Cipher>,
    format: ExportFormat,
) -> Result<String, ExportError> {
    let enc = client.internal.get_encryption_settings()?;
    let key = enc.get_key(&None)?;

    let folders: Vec<FolderView> = folders.decrypt_with_key(key)?;
    let folders: Vec<crate::Folder> = folders.into_iter().flat_map(|f| f.try_into()).collect();

    let ciphers: Vec<crate::Cipher> = ciphers
        .into_iter()
        .flat_map(|c| crate::Cipher::from_cipher(&enc, c))
        .collect();

    match format {
        ExportFormat::Csv => Ok(export_csv(folders, ciphers)?),
        ExportFormat::Json => Ok(export_json(folders, ciphers)?),
        ExportFormat::EncryptedJson { password } => Ok(export_encrypted_json(
            folders,
            ciphers,
            password,
            client.internal.get_kdf()?,
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

/// See [crate::ClientExporters::export_cxf] for more documentation.
pub(crate) fn export_cxf(
    client: &Client,
    account: Account,
    ciphers: Vec<Cipher>,
) -> Result<String, ExportError> {
    let enc = client.internal.get_encryption_settings()?;

    let ciphers: Vec<crate::Cipher> = ciphers
        .into_iter()
        .flat_map(|c| crate::Cipher::from_cipher(&enc, c))
        .collect();

    Ok(build_cxf(account, ciphers)?)
}

fn encrypt_import(enc: &dyn KeyContainer, cipher: ImportingCipher) -> Result<Cipher, ExportError> {
    let mut view: CipherView = cipher.clone().into();

    // Get passkey from cipher if cipher is type login
    let passkey = match cipher.r#type {
        crate::CipherType::Login(login) => login.fido2_credentials,
        _ => None,
    };

    if let Some(passkey) = passkey {
        let passkeys = passkey.into_iter().map(|p| p.into()).collect();

        view.set_new_fido2_credentials(enc, passkeys)?;
    }

    let key = view.locate_key(enc, &None)?;
    let new_cipher = view.encrypt_with_key(key)?;

    Ok(new_cipher)
}

/// See [crate::ClientExporters::import_cxf] for more documentation.
pub(crate) fn import_cxf(client: &Client, payload: String) -> Result<Vec<Cipher>, ExportError> {
    let enc = client.internal.get_encryption_settings()?;

    let ciphers = parse_cxf(payload)?;
    let ciphers: Result<Vec<Cipher>, _> = ciphers
        .into_iter()
        .map(|c| encrypt_import(&enc, c))
        .collect();

    ciphers
}
