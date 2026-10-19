use bitwarden_core::Client;

#[allow(missing_docs)]
#[derive(Clone)]
#[bitwarden_ffi::wasm_object]
pub struct CommercialVaultClient {
    #[allow(unused)]
    pub(crate) client: Client,
}

impl CommercialVaultClient {
    fn new(client: Client) -> Self {
        Self { client }
    }
}

#[bitwarden_ffi::wasm_export]
impl CommercialVaultClient {}

#[allow(missing_docs)]
pub trait CommercialVaultClientExt {
    fn vault(&self) -> CommercialVaultClient;
}

impl CommercialVaultClientExt for Client {
    fn vault(&self) -> CommercialVaultClient {
        CommercialVaultClient::new(self.clone())
    }
}
