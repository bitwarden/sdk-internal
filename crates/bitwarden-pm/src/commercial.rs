use bitwarden_commercial_vault::CommercialVaultClientExt as _;

pub struct CommercialPasswordManagerClient(bitwarden_core::Client);

impl CommercialPasswordManagerClient {
    pub(crate) fn new(client: bitwarden_core::Client) -> Self {
        Self(client)
    }

    /// Vault item operations
    pub fn vault(&self) -> bitwarden_commercial_vault::CommercialVaultClient {
        self.0.vault()
    }
}
