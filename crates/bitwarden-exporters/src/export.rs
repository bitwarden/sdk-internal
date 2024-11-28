use bitwarden_core::Client;
use bitwarden_crypto::{KeyContainer, KeyDecryptable, KeyEncryptable, SymmetricCryptoKey};
use bitwarden_vault::{
    Cipher, CipherView, Collection, Fido2CredentialFullView, Folder, FolderView,
};

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

/// Credential Exchange Format (CXF)
///
/// *Warning:* Expect this API to be unstable, and it will change in the future.
///
/// For use with Apple using [ASCredentialExportManager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager).
/// Ideally the input should be immediately serialized from [ASImportableAccount](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
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

fn encrypt_import(
    key: &SymmetricCryptoKey,
    cipher: ImportingCipher,
) -> Result<Cipher, ExportError> {
    let view: CipherView = cipher.clone().into();

    let mut new_cipher = view.encrypt_with_key(key)?;

    //  Get passkey from cipher
    // if cipher is typpe login
    let passkey = match cipher.r#type {
        crate::CipherType::Login(login) => login.fido2_credentials,
        _ => None,
    };

    if let Some(passkey) = passkey {
        let psk: Vec<bitwarden_vault::Fido2Credential> = passkey
            .into_iter()
            .flat_map(|p| {
                Fido2CredentialFullView {
                    credential_id: p.credential_id,
                    key_type: p.key_type,
                    key_algorithm: p.key_algorithm,
                    key_curve: p.key_curve,
                    key_value: p.key_value,
                    rp_id: p.rp_id,
                    user_handle: p.user_handle,
                    user_name: p.user_name,
                    counter: p.counter.to_string(),
                    rp_name: p.rp_name,
                    user_display_name: p.user_display_name,
                    discoverable: p.discoverable,
                    creation_date: p.creation_date,
                }
                .encrypt_with_key(key)
            })
            .collect();

        let login = new_cipher.login.as_mut().unwrap();
        login.fido2_credentials = Some(psk);

        new_cipher.login = Some(login.clone());
    }

    Ok(new_cipher)
}

/// Credential Exchange Format (CXF)
///
/// *Warning:* Expect this API to be unstable, and it will change in the future.
///
/// For use with Apple using [ASCredentialExportManager](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager).
/// Ideally the input should be immediately serialized from [ASImportableAccount](https://developer.apple.com/documentation/authenticationservices/asimportableaccount).
pub(crate) fn import_cxf(client: &Client, payload: String) -> Result<Vec<Cipher>, ExportError> {
    let enc = client.internal.get_encryption_settings()?;
    let key = enc.get_key(&None)?;

    let ciphers = parse_cxf(payload)?;
    let ciphers: Result<Vec<Cipher>, _> = ciphers
        .into_iter()
        .map(|c| encrypt_import(key, c))
        .collect();

    ciphers
}
