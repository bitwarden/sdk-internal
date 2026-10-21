use bitwarden_core::Client;

use crate::{
    Credentials, ImportError, ImportOptions, ImportSummary, OnePasswordImportSummary,
    OnePasswordSignInMethods, OnePasswordSsoCredentials, OnePasswordSsoUi, OnePasswordTwoFactorUi,
    SignInAddress,
    import::{
        import_kdbx, import_onepassword, import_onepassword_sso, onepassword_sign_in_methods,
    },
};

#[allow(missing_docs)]
#[bitwarden_ffi::wasm_object]
pub struct ImporterClient {
    client: Client,
}

#[bitwarden_ffi::wasm_export]
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

    /// Asks 1Password how the account signs in: with the password and Secret Key, with SSO, or
    /// either. It needs only the email and the sign-in address, so the UI can call it first and
    /// then ask for the password and Secret Key or start
    /// [`ImporterClient::import_onepassword_sso`]. Fails with
    /// [`ImportError::OnePasswordInvalidEmail`] when 1Password refuses the email as malformed.
    pub async fn onepassword_sign_in_methods(
        &self,
        username: String,
        sign_in_address: SignInAddress,
    ) -> Result<OnePasswordSignInMethods, ImportError> {
        onepassword_sign_in_methods(&self.client, username, sign_in_address).await
    }
}

#[cfg(feature = "wasm")]
#[bitwarden_ffi::wasm_export]
impl ImporterClient {
    /// The same import as [`ImporterClient::import_onepassword`], for JavaScript, which passes the
    /// two-factor prompt as an object rather than a `&dyn` callback.
    #[wasm_bindgen(js_name = import_onepassword)]
    pub async fn import_onepassword_wasm(
        &self,
        credentials: Credentials,
        two_factor: crate::wasm::RawJsOnePasswordTwoFactorUi,
        options: ImportOptions,
    ) -> Result<OnePasswordImportSummary, ImportError> {
        let two_factor = crate::wasm::JsOnePasswordTwoFactorUi::new(two_factor);
        import_onepassword(&self.client, credentials, &two_factor, options).await
    }

    /// The same import as [`ImporterClient::import_onepassword_sso`], for JavaScript, which passes
    /// the callbacks as objects rather than `&dyn` references.
    #[wasm_bindgen(js_name = import_onepassword_sso)]
    pub async fn import_onepassword_sso_wasm(
        &self,
        credentials: OnePasswordSsoCredentials,
        ui: crate::wasm::RawJsOnePasswordSsoUi,
        options: ImportOptions,
    ) -> Result<OnePasswordImportSummary, ImportError> {
        let ui = crate::wasm::JsOnePasswordSsoUi::new(ui);
        import_onepassword_sso(&self.client, credentials, &ui, options).await
    }
}

// Separate from the block above: `wasm_bindgen` cannot export the `&dyn` callbacks.
impl ImporterClient {
    /// Import a 1Password account directly from the 1Password servers.
    ///
    /// Signs in with the email, master password and Secret Key in `credentials`, asking
    /// `two_factor` for a code when the account requires one, downloads and decrypts every vault
    /// the account can open, and submits the result to the import endpoint. Each vault becomes a
    /// folder. Returns the imported counts plus any vaults or items that could not be imported.
    pub async fn import_onepassword(
        &self,
        credentials: Credentials,
        two_factor: &dyn OnePasswordTwoFactorUi,
        options: ImportOptions,
    ) -> Result<OnePasswordImportSummary, ImportError> {
        import_onepassword(&self.client, credentials, two_factor, options).await
    }

    /// The same import as [`ImporterClient::import_onepassword`], signing in with single sign-on.
    ///
    /// Signs in with the email and sign-in address in `credentials` through the account's identity
    /// provider, which `ui` opens for the user. Every import is a new device for the account, so
    /// the user approves it from another 1Password device and types the verification code it
    /// shows, again through `ui`. A sign-in the user gives up on, at the identity provider or
    /// during the approval, ends with `ImportError::OnePasswordCanceled`, and one the approving
    /// device denies with `ImportError::OnePasswordDenied`.
    pub async fn import_onepassword_sso(
        &self,
        credentials: OnePasswordSsoCredentials,
        ui: &dyn OnePasswordSsoUi,
        options: ImportOptions,
    ) -> Result<OnePasswordImportSummary, ImportError> {
        import_onepassword_sso(&self.client, credentials, ui, options).await
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
