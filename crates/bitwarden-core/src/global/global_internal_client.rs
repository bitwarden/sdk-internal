use std::sync::Arc;

use crate::client::internal::ApiConfigurations;

#[allow(missing_docs)]
pub struct GlobalInternalClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

impl GlobalInternalClient {
    /// Get the `ApiConfigurations` containing API clients and configurations for making
    /// unauthenticated requests to the Bitwarden services.
    pub fn get_api_configurations(&self) -> Arc<ApiConfigurations> {
        self.api_configurations.clone()
    }
}
