use std::sync::Arc;

use bitwarden_core::client::ApiConfigurations;

mod delete;
mod download_url;

pub use delete::DeleteAttachmentAdminError;
pub use download_url::CipherAdminGetAttachmentDownloadUrlError;

/// Wrapper for attachment admin operations. Uses the admin server API endpoints and does
/// not modify local state.
#[bitwarden_ffi::wasm_object]
pub struct AttachmentAdminClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}
