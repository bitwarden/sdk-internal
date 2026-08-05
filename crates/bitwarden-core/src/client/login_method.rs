use bitwarden_crypto::Kdf;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum LoginMethod {
    #[allow(dead_code)]
    User(UserLoginMethod),
    // TODO: Organizations supports api key
    // Organization(OrganizationLoginMethod),
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
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
