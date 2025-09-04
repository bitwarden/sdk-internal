use bitwarden_core::Client;
use bitwarden_wasm_internal::BitwardenClient;
use wasm_bindgen::prelude::*;

#[allow(missing_docs)]
#[wasm_bindgen]
pub struct CommercialBitwardenClient(Client);

#[wasm_bindgen]
impl CommercialBitwardenClient {
    #[allow(missing_docs)]
    #[wasm_bindgen(constructor)]
    pub fn new(client: BitwardenClient) -> Self {
        Self(client.0.clone())
    }

    /// Test method, echoes back the input
    pub fn echo(&self, msg: String) -> String {
        msg
    }

    #[allow(missing_docs)]
    pub fn vault(&self) -> BitVaultClient {
        BitVaultClient::new(self.0.clone())
    }

    #[allow(missing_docs)]
    pub fn version(&self) -> String {
        format!("COMMERCIAL-{}", env!("SDK_VERSION"))
    }
}

#[wasm_bindgen]
#[allow(unused)]
pub struct BitVaultClient(Client);

impl BitVaultClient {
    pub fn new(client: Client) -> Self {
        Self(client.clone())
    }
}
