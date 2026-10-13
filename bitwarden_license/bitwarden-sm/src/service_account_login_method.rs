use std::path::PathBuf;

use bitwarden_core::OrganizationId;

use crate::AccessToken;

/// Login method for a Secrets Manager service account.
#[derive(Debug)]
pub enum ServiceAccountLoginMethod {
    AccessToken {
        access_token: AccessToken,
        organization_id: OrganizationId,
        state_file: Option<PathBuf>,
    },
}
