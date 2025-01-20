use bitwarden_core::Client;

use crate::{
    sync::{sync, SyncError},
    SyncRequest, SyncResponse,
};

/// A vault client.
///
/// # Examples
///
/// ```rust
/// use bitwarden_core::{Client,ClientSettings,DeviceType};
/// use bitwarden_vault::VaultClient;
///
/// let client = Client::new(Some(ClientSettings {
///     identity_url: "https://identity.bitwarden.com".to_owned(),
///     api_url: "https://api.bitwarden.com".to_owned(),
///     user_agent: "Bitwarden Rust-SDK".to_owned(),
///     device_type: DeviceType::ChromeBrowser,
/// }));
///
/// let vault = VaultClient::new(&client);
/// ```
pub struct VaultClient<'a> {
    /// A vault client.
    pub(crate) client: &'a Client,
}

impl<'a> VaultClient<'a> {
    /// Constructs a new [VaultClient] with the given [Client]
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitwarden_core::{Client,ClientSettings,DeviceType};
    /// # use bitwarden_vault::VaultClient;
    /// # let client = Client::new(Some(ClientSettings {
    /// #     identity_url: "https://identity.bitwarden.com".to_owned(),
    /// #     api_url: "https://api.bitwarden.com".to_owned(),
    /// #     user_agent: "Bitwarden Rust-SDK".to_owned(),
    /// #     device_type: DeviceType::ChromeBrowser,
    /// # }));
    /// let vault = VaultClient::new(&client);
    /// let ciphers = vault.ciphers();
    /// // ...
    /// ```
    pub fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Syncs the [VaultClient] with the server.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use bitwarden_core::{Client,ClientSettings,DeviceType};
    /// # use bitwarden_vault::{VaultClient,SyncRequest, SyncResponse};
    /// async fn sync_vault(client: &Client) {
    ///     let vault = VaultClient::new(client);
    ///     let request = SyncRequest {
    ///        exclude_subdomains: Some(false),
    ///     };
    ///
    ///     let result = vault.sync(&request).await;
    ///     match result {
    ///         Ok(response) => println!("Response: {:?}", response),
    ///         Err(error) => {
    ///             eprintln!("Sync failed: {:?}", error);
    ///         },
    ///     }
    /// }
    /// ```
    pub async fn sync(&self, input: &SyncRequest) -> Result<SyncResponse, SyncError> {
        sync(self.client, input).await
    }
}

/// An extension trait for the [VaultClient] struct to provide vault functionality.
pub trait VaultClientExt<'a> {
    fn vault(&'a self) -> VaultClient<'a>;
}

impl<'a> VaultClientExt<'a> for Client {
    fn vault(&'a self) -> VaultClient<'a> {
        VaultClient::new(self)
    }
}
