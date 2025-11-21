use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[expect(missing_docs)]
#[derive(Clone)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct CommercialVaultClient {
    #[expect(unused)]
    pub(crate) client: Client,
}

impl CommercialVaultClient {
    fn new(client: Client) -> Self {
        Self { client }
    }
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CommercialVaultClient {}

#[expect(missing_docs)]
pub trait CommercialVaultClientExt {
    fn vault(&self) -> CommercialVaultClient;
}

impl CommercialVaultClientExt for Client {
    fn vault(&self) -> CommercialVaultClient {
        CommercialVaultClient::new(self.clone())
    }
}
