use wasm_bindgen::prelude::*;

#[allow(missing_docs)]
#[wasm_bindgen]
pub struct CommercialBitwardenClient();
// pub struct CommercialBitwardenClient(pub(crate) Client);

#[wasm_bindgen]
impl CommercialBitwardenClient {
    #[allow(missing_docs)]
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self()
        // Self(Client::new())
    }

    /// Test method, echoes back the input
    pub fn echo(&self, msg: String) -> String {
        msg
    }

    #[allow(missing_docs)]
    pub fn version(&self) -> String {
        format!("COMMERCIAL-{}", env!("SDK_VERSION"))
    }
}
