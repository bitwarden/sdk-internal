#[cfg(feature = "secrets")]
use std::path::PathBuf;

use bitwarden_crypto::Kdf;

#[cfg(feature = "secrets")]
use crate::{OrganizationId, auth::AccessToken};

#[derive(Debug)]
pub enum LoginMethod {
    #[allow(dead_code)]
    User(UserLoginMethod),
    // TODO: Organizations supports api key
    // Organization(OrganizationLoginMethod),
    #[cfg(feature = "secrets")]
    ServiceAccount(ServiceAccountLoginMethod),
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum UserLoginMethod {
    Username {
        client_id: String,
        email: String,
        kdf: Kdf,
    },
    ApiKey {
        client_id: String,
        client_secret: String,

        email: String,
        kdf: Kdf,
    },
}

#[cfg(feature = "secrets")]
#[derive(Debug)]
pub enum ServiceAccountLoginMethod {
    AccessToken {
        access_token: AccessToken,
        organization_id: OrganizationId,
        state_file: Option<PathBuf>,
    },
}
