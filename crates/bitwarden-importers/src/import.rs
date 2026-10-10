//! Routing: maps each importer's public entry to its parser + the generic submit pipeline.

use bitwarden_core::Client;

use crate::{
    Credentials, ImportError, ImportOptions, ImportSummary, OnePasswordImportSummary,
    OnePasswordTwoFactorUi,
    importers::{
        self,
        onepassword::{access, convert},
    },
    pipeline,
};

/// See [crate::ImporterClient::import_kdbx] for more documentation.
pub(crate) async fn import_kdbx(
    client: &Client,
    file: Vec<u8>,
    password: Option<String>,
    key_file: Option<Vec<u8>>,
    options: ImportOptions,
) -> Result<ImportSummary, ImportError> {
    let parsed = importers::kdbx::parse(file, password, key_file)?;
    pipeline::submit_import(client, parsed, options).await
}

/// See [crate::ImporterClient::import_onepassword] for more documentation.
pub(crate) async fn import_onepassword(
    client: &Client,
    credentials: Credentials,
    two_factor: &dyn OnePasswordTwoFactorUi,
    options: ImportOptions,
) -> Result<OnePasswordImportSummary, ImportError> {
    // 1Password is a third-party host, so this goes through the client's external transport rather
    // than the one configured for the Bitwarden API.
    let onepassword = access::Client::new(client.internal.get_http_client().clone());
    let mut account = onepassword.open_account(credentials, two_factor).await?;
    let skipped_items = account
        .vaults
        .iter_mut()
        .flat_map(|vault| std::mem::take(&mut vault.skipped_items))
        .collect();
    let imported =
        pipeline::submit_import(client, convert::convert(account.vaults), options).await?;

    Ok(OnePasswordImportSummary {
        imported,
        skipped_vaults: account.skipped_vaults,
        skipped_items,
    })
}
