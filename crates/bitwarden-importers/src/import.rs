//! Routing: maps each importer's public entry to its parser + the generic submit pipeline.

use bitwarden_core::Client;

use crate::{ImportError, ImportOptions, ImportSummary, importers, pipeline};

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
