//! The cryptographic half of connector registration. Key material is minted by
//! `bitwarden-access-token`.

use bitwarden_access_token::{AccessTokenKind, AccessTokenSecrets, make_access_token_secrets};
use bitwarden_core::{OrganizationId, key_management::SymmetricKeySlotId};

use super::{connectors::AccessConnectorsClient, error::RotationError};

impl AccessConnectorsClient {
    /// Generates the key material a connector registration needs.
    ///
    /// Fails with [`MissingOrganizationKey`](RotationError::MissingOrganizationKey) for a caller
    /// whose key store holds no key for the organization (not a member, or an unpopulated store).
    pub(super) fn registration_secrets(
        &self,
        organization_id: OrganizationId,
    ) -> Result<AccessTokenSecrets, RotationError> {
        let organization_key = SymmetricKeySlotId::Organization(organization_id);
        let mut ctx = self.key_store.context_mut();

        if !ctx.has_symmetric_key(organization_key) {
            return Err(RotationError::MissingOrganizationKey);
        }

        Ok(make_access_token_secrets(
            &mut ctx,
            organization_key,
            AccessTokenKind::AccessConnector,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::{
        client::ApiConfigurations, key_management::create_test_crypto_with_user_key,
    };
    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use uuid::uuid;

    use super::*;

    fn organization_id() -> OrganizationId {
        OrganizationId::new(uuid!("11111111-1111-1111-1111-111111111111"))
    }

    #[test]
    fn registering_without_the_organization_key_fails_before_any_network_call() {
        let client = AccessConnectorsClient {
            // A store with a user key but no organization key, as for a non-member.
            key_store: create_test_crypto_with_user_key(SymmetricCryptoKey::make(
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            )),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(
                ApiClient::new_mocked(|_| {}),
            )),
        };

        let result = client.registration_secrets(organization_id());

        assert!(matches!(result, Err(RotationError::MissingOrganizationKey)));
    }
}
