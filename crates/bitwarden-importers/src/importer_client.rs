use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Credentials, ImportError, ImportOptions, ImportSummary, OnePasswordTwoFactorUi,
    import::{import_kdbx, import_onepassword},
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
}

// Separate from the block above: `wasm_bindgen` cannot export the `&dyn` two-factor callback.
impl ImporterClient {
    /// Import a 1Password account directly from the 1Password servers.
    ///
    /// Signs in with the email, master password and Secret Key in `credentials`, asking
    /// `two_factor` for a code when the account requires one, downloads and decrypts every vault
    /// the account can open, and submits the result to the import endpoint. Each vault becomes a
    /// folder. Returns the counts of what was imported.
    pub async fn import_onepassword(
        &self,
        credentials: Credentials,
        two_factor: &dyn OnePasswordTwoFactorUi,
        options: ImportOptions,
    ) -> Result<ImportSummary, ImportError> {
        import_onepassword(&self.client, credentials, two_factor, options).await
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
