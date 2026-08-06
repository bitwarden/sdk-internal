use std::sync::Arc;

use bitwarden_core::client::ApiConfigurations;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

mod delete;
mod download_url;

pub use delete::DeleteAttachmentAdminError;
pub use download_url::CipherAdminGetAttachmentDownloadUrlError;

/// Wrapper for attachment admin operations. Uses the admin server API endpoints and does
/// not modify local state.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct AttachmentAdminClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}
