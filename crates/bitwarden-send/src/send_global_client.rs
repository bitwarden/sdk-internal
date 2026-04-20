use bitwarden_core::global::GlobalClient;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{SendAuthType, SendDecryptError, SendView};

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct SendGlobalClient {
    pub(crate) client: GlobalClient,
}

impl SendGlobalClient {
    fn new(client: GlobalClient) -> Self {
        Self { client }
    }

    pub async fn receive_send(
        &self,
        id: &str,
        auth: &SendAuthType,
    ) -> Result<SendView, SendDecryptError> {
        todo!()
    }
}

#[allow(missing_docs)]
pub trait SendGlobalClientExt {
    fn sends(&self) -> SendGlobalClient;
}

impl SendGlobalClientExt for GlobalClient {
    fn sends(&self) -> SendGlobalClient {
        SendGlobalClient::new(self.clone())
    }
}
