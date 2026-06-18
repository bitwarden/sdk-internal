use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    ImportError, ImportOptions, ImportSummary, import::import_kdbx, keeper::KeeperCryptoClient,
};

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct ImporterClient {
    client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl ImporterClient {
    fn new(client: Client) -> Self {
        Self { client }
    }

    /// Import a KeePass KDBX (`.kdbx`) database and submit it to the server.
    ///
    /// Parses and decrypts the raw `.kdbx` bytes (unlocked with the password and/or key file),
    /// encrypts the entries for the user's personal vault or the given organization, and submits
    /// them to the import endpoint. Returns the counts of what was imported. Inputs larger than
    /// 10 MiB are rejected with `KdbxFileTooLarge`.
    pub async fn import_kdbx(
        &self,
        file: Vec<u8>,
        password: Option<String>,
        key_file: Option<Vec<u8>>,
        options: ImportOptions,
    ) -> Result<ImportSummary, ImportError> {
        import_kdbx(&self.client, file, password, key_file, options).await
    }

    /// Keeper "direct" importer cryptography.
    ///
    /// Returns a stateless client exposing Keeper's wire-format crypto primitives, used by the
    /// Keeper direct importer while its access layer is migrated from TypeScript.
    pub fn keeper_crypto(&self) -> KeeperCryptoClient {
        KeeperCryptoClient
    }
}

#[allow(missing_docs)]
pub trait ImporterClientExt {
    fn importers(&self) -> ImporterClient;
}

impl ImporterClientExt for Client {
    fn importers(&self) -> ImporterClient {
        ImporterClient::new(self.clone())
    }
}
