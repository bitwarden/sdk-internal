use bitwarden_core::Client;
use wasm_bindgen::prelude::*;

mod create;
mod delete;
mod edit;
mod get;
mod restore;

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct CipherAdminClient {
    pub(crate) client: Client,
}
