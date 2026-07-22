//! `reinit_user_crypto`: refresh an unlocked user's cryptographic state
//! intended to be used for mobile clients.

#![cfg(feature = "uniffi")]

use bitwarden_crypto::SymmetricKeyAlgorithm;
use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::{
    Client,
    key_management::{
        SymmetricKeySlotId, V2UpgradeToken,
        account_cryptographic_state::WrappedAccountCryptographicState,
    },
};

/// State used to re-initialize an unlocked user's cryptographic state after
/// `accountCryptographicState` and `V2UpgradeToken` are received in a sync.
///
/// This presumes the SDK is already unlocked (has user key in memory).
#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ReinitUserCryptoRequest {
    /// The user's account cryptographic state, encrypted under the user key
    pub account_cryptographic_state: WrappedAccountCryptographicState,

    /// The SDK uses the in-store (V1) user key to extract the V2 user key from the token,
    /// then sets the V2 user key as the active user key before decrypting
    /// `account_cryptographic_state`.
    pub upgrade_token: V2UpgradeToken,
}

/// Errors that can occur when re-initializing user cryptography state.
#[derive(Debug, Error)]
#[bitwarden_error(flat)]
pub enum ReinitUserCryptoError {
    /// The SDK is not in an unlocked state, so it cannot re-initialize user crypto.
    #[error("The SDK must be unlocked to re-initialize user crypto")]
    NotUnlocked,
    /// The provided account cryptographic state is not V2. Re-initialization is only supported for
    /// upgrading to V2 encryption.
    #[error(
        "The provided account cryptographic state is not V2. Re-initialization is only supported for upgrading to V2 encryption."
    )]
    InvalidAccountCryptographicState,
    /// The local migrations (pin key and local user data key) that runs as part of the V1->V2
    /// upgrade failed, likely due to missing state or keys that should be present during the
    /// upgrade process. Clients should deconstruct the SDK and initialize a fresh instance to
    /// recover.
    #[error("Unable to run local migrations after user key upgrade")]
    LocalMigrationFailed,
    /// The provided upgrade token was invalid, such as not decrypting properly with the active user
    /// key, or containing unexpected data.
    #[error("Invalid upgrade token")]
    InvalidUpgradeToken,
    /// An error occurred during the cryptographic operations to re-initialize user crypto.
    #[error("Cryptography Initialization error")]
    CryptoInitialization,
    /// The SDK does not have a state bridge registered, which is required to perform V1->V2 local
    /// data migrations.
    #[error("No state bridge registered, re-initialization is not supported")]
    StateBridgeNotRegistered,
}

/// Re-initialize the user's cryptographic state during an unlock session for a V1 -> V2 upgrade.
/// If the user is already V2 this function is a no-op.
///
/// Requires the SDK to be unlocked and the client to have registered a state bridge. Replaces the
/// in-memory account cryptographic state with the provided one, and upgrades the active user key
/// from V1 to V2. Performs local data migrations for the local user data key and pin key.
///
/// Intended for mobile clients with `accountCryptographicState` and `V2UpgradeToken` received in
/// a sync for a V1 -> V2 encryption upgrade. This allows the client to apply the received account
/// cryptographic state and update to reinitialize the SDK without tearing down and recreating the
/// client.
pub(crate) async fn reinit_user_crypto(
    client: &Client,
    req: ReinitUserCryptoRequest,
) -> Result<(), ReinitUserCryptoError> {
    if !matches!(
        req.account_cryptographic_state,
        WrappedAccountCryptographicState::V2 { .. }
    ) {
        return Err(ReinitUserCryptoError::InvalidAccountCryptographicState);
    }

    if !client.internal.state_bridge.is_registered() {
        warn!("No state bridge registered, re-initialization is not supported.");
        return Err(ReinitUserCryptoError::StateBridgeNotRegistered);
    }

    {
        let mut ctx = client.internal.get_key_store().context_mut();

        if !ctx.has_symmetric_key(SymmetricKeySlotId::User) {
            return Err(ReinitUserCryptoError::NotUnlocked);
        }

        let current_algorithm = ctx
            .get_symmetric_key_algorithm(SymmetricKeySlotId::User)
            .map_err(|_| ReinitUserCryptoError::CryptoInitialization)?;

        let local_v2_user_key_id = match current_algorithm {
            SymmetricKeyAlgorithm::Aes256CbcHmac => {
                info!("V1 user key detected with upgrade token, extracting V2 key");
                req.upgrade_token
                    .unwrap_v2(SymmetricKeySlotId::User, &mut ctx)
                    .map_err(|_| ReinitUserCryptoError::InvalidUpgradeToken)?
            }
            SymmetricKeyAlgorithm::XChaCha20Poly1305 | SymmetricKeyAlgorithm::XAes256Gcm => {
                // If the active user key is already V2, then the upgrade token should not be
                // applied. We return here so calling reinit_user_crypto with the
                // same sync payload after a successful V2 upgrade is a no-op.
                debug!("Active user key is already V2, skipping re-initialization.");
                return Ok(());
            }
            SymmetricKeyAlgorithm::Aes256Gcm => {
                error!("Unexpected AES-256-GCM user key during reinit_user_crypto");
                return Err(ReinitUserCryptoError::CryptoInitialization);
            }
        };

        req.account_cryptographic_state
            .set_to_context(
                &client.internal.security_state,
                local_v2_user_key_id,
                client.internal.get_key_store(),
                ctx,
            )
            .map_err(|e| {
                error!(error = ?e, "Failed to set account cryptographic state to context during reinit_user_crypto");
                ReinitUserCryptoError::CryptoInitialization
            })?;
    }

    client
        .internal
        .state_bridge
        .set_v2_upgrade_token(&req.upgrade_token)
        .await;

    super::on_unlock_handler(client).await.map_err(|e| {
        error!(error = ?e, "Failure in on_unlock_handler during reinit_user_crypto.");
        ReinitUserCryptoError::LocalMigrationFailed
    })?;

    info!("User crypto re-initialized successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{EncString, KeyStore, SymmetricCryptoKey, SymmetricKeyAlgorithm};

    use super::*;
    use crate::{
        Client, UserId,
        client::test_accounts::{test_bitwarden_com_account, test_bitwarden_com_account_v2},
        key_management::{
            KeySlotIds, PrivateKeySlotId, SigningKeySlotId, V2UpgradeToken,
            state_bridge::test_support::InMemoryStateBridge,
        },
    };

    // v2
    const TEST_VECTOR_USER_KEY_V2_B64: &str = "pQEEAlACHUUoybNAuJoZzqNMxz2bAzoAARFvBIQDBAUGIFggAvGl4ifaUAomQdCdUPpXLHtypiQxHjZwRHeI83caZM4B";
    const TEST_VECTOR_PRIVATE_KEY_V2: &str = "7.g1gdowE6AAERbwMZARwEUAIdRSjJs0C4mhnOo0zHPZuhBVgYthGLGqVLPeidY8mNMxpLJn3fyeSxyaWsWQTR6pxmRV2DyGZXly/0l9KK+Rsfetl9wvYIz0O4/RW3R6wf7eGxo5XmicV3WnFsoAmIQObxkKWShxFyjzg+ocKItQDzG7Gp6+MW4biTrAlfK51ML/ZS+PCjLmgI1QQr4eMHjiwA2TBKtKkxfjoTJkMXECpRVLEXOo8/mbIGYkuabbSA7oU+TJ0yXlfKDtD25gnyO7tjW/0JMFUaoEKRJOuKoXTN4n/ks4Hbxk0X5/DzfG05rxWad2UNBjNg7ehW99WrQ+33ckdQFKMQOri/rt8JzzrF1k11/jMJ+Y2TADKNHr91NalnUX+yqZAAe3sRt5Pv5ZhLIwRMKQi/1NrLcsQPRuUnogVSPOoMnE/eD6F70iU60Z6pvm1iBw2IvELZcrs/oxpO2SeCue08fIZW/jNZokbLnm90tQ7QeZTUpiPALhUgfGOa3J9VOJ7jQGCqDjd9CzV2DCVfhKCapeTbldm+RwEWBz5VvorH5vMx1AzbPRJxdIQuxcg3NqRrXrYC7fyZljWaPB9qP1tztiPtd1PpGEgxLByIfR6fqyZMCvOBsWbd0H6NhF8mNVdDw60+skFRdbRBTSCjCtKZeLVuVFb8ioH45PR5oXjtx4atIDzu6DKm6TTMCbR6DjZuZZ8GbwHxuUD2mDD3pAFhaof9kR3lQdjy7Zb4EzUUYskQxzcLPcqzp9ZgB3Rg91SStBCCMhdQ6AnhTy+VTGt/mY5AbBXNRSL6fI0r+P9K8CcEI4bNZCDkwwQr5v4O4ykSUzIvmVU0zKzDngy9bteIZuhkvGUoZlQ9UATNGPhoLfqq2eSvqEXkCbxTVZ5D+Ww9pHmWeVcvoBhcl5MvicfeQt++dY3tPjIfZq87nlugG4HiNbcv9nbVpgwe3v8cFetWXQgnO4uhx8JHSwGoSuxHFZtl2sdahjTHavRHnYjSABEFrViUKgb12UDD5ow1GAL62wVdSJKRf9HlLbJhN3PBxuh5L/E0wy1wGA9ecXtw/R1ktvXZ7RklGAt1TmNzZv6vI2J/CMXvndOX9rEpjKMbwbIDAjQ9PxiWdcnmc5SowT9f6yfIjbjXnRMWWidPAua7sgrtej4HP4Qjz1fpgLMLCRyF97tbMTmsAI5Cuj98Buh9PwcdyXj5SbVuHdJS1ehv9b5SWPsD4pwOm3+otVNK6FTazhoUl47AZoAoQzXfsXxrzqYzvF0yJkCnk9S1dcij1L569gQ43CJO6o6jIZFJvA4EmZDl95ELu+BC+x37Ip8dq4JLPsANDVSqvXO9tfDUIXEx25AaOYhW2KAUoDve/fbsU8d0UZR1o/w+ZrOQwawCIPeVPtbh7KFRVQi/rPI+Abl6XR6qMJbKPegliYGUuGF2oEMEc6QLTsMRCEPuw0S3kxbNfVPqml8nGhB2r8zUHBY1diJEmipVghnwH74gIKnyJ2C9nKjV8noUfKzqyV8vxUX2G5yXgodx8Jn0cWs3XhWuApFla9z4R28W/4jA1jK2WQMlx+b6xKUWgRk8+fYsc0HSt2fDrQ9pLpnjb8ME59RCxSPV++PThpnR2JtastZBZur2hBIJsGILCAmufUU4VC4gBKPhNfu/OK4Ktgz+uQlUa9fEC/FnkpTRQPxHuQjSQSNrIIyW1bIRBtnwjvvvNoui9FZJ";
    const TEST_VECTOR_SIGNED_PUBLIC_KEY_V2: &str = "hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8BoFkBTqNpYWxnb3JpdGhtAG1jb250ZW50Rm9ybWF0AGlwdWJsaWNLZXlZASYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDP/7WM8nUepxoJ0qtM+azxcly+eZ31qUjjZTZcX/gYw1MzkoXWAjqyeFH/bdktq1lEUwegrxkIxKkY2SMtp0CvPnaV1x5O8E6FBSJbKWRlDg181rfEhgm5tc6aR4PJ827IvFVm9xk6Sj091P5DHZDEOsWLZc2jYjtpUV3X38I4gSR7HiYnR4DcwcWkoJ3FhtxMCwYgPz6RVH0vzhLUmm1mgbzH6IH8Pf9DjLTZSxBikVO7S9s9jzhiZbTeeAl3FbNLxfj9Qkj+NoSfms7jGVTlBwvSXgjJs/ktGkT1cR5QcBMpU4bt41+l73MN8pXapCih9Awf1W+RY7imxpYOMFJ3AgMBAAFYQMq/hT4wod2w8xyoM7D86ctuLNX4ZRo+jRHf2sZfaO7QsvonG/ZYuNKF5fq8wpxMRjfoMvnY2TTShbgzLrW8BA4=";
    const TEST_VECTOR_SIGNING_KEY_V2: &str = "7.g1gcowE6AAERbwMYZQRQAh1FKMmzQLiaGc6jTMc9m6EFWBhYePc2qkCruHAPXgbzXsIP1WVk11ArbLNYUBpifToURlwHKs1je2BwZ1C/5thz4nyNbL0wDaYkRWI9ex1wvB7KhdzC7ltStEd5QttboTSCaXQROSZaGBPNO5+Bu3sTY8F5qK1pBUo6AHNN";
    const TEST_VECTOR_SECURITY_STATE_V2: &str = "hFgepAEnAxg8BFAmkP0QgfdMVbIujX55W/yNOgABOH8CoFgkomhlbnRpdHlJZFBHOOw2BI9OQoNq+Vl1xZZKZ3ZlcnNpb24CWEAlchbJR0vmRfShG8On7Q2gknjkw4Dd6MYBLiH4u+/CmfQdmjNZdf6kozgW/6NXyKVNu8dAsKsin+xxXkDyVZoG";

    // v1
    const TEST_VECTOR_PRIVATE_KEY_V1: &str = "2.yN7l00BOlUE0Sb0M//Q53w==|EwKG/BduQRQ33Izqc/ogoBROIoI5dmgrxSo82sgzgAMIBt3A2FZ9vPRMY+GWT85JiqytDitGR3TqwnFUBhKUpRRAq4x7rA6A1arHrFp5Tp1p21O3SfjtvB3quiOKbqWk6ZaU1Np9HwqwAecddFcB0YyBEiRX3VwF2pgpAdiPbSMuvo2qIgyob0CUoC/h4Bz1be7Qa7B0Xw9/fMKkB1LpOm925lzqosyMQM62YpMGkjMsbZz0uPopu32fxzDWSPr+kekNNyLt9InGhTpxLmq1go/pXR2uw5dfpXc5yuta7DB0EGBwnQ8Vl5HPdDooqOTD9I1jE0mRyuBpWTTI3FRnu3JUh3rIyGBJhUmHqGZvw2CKdqHCIrQeQkkEYqOeJRJVdBjhv5KGJifqT3BFRwX/YFJIChAQpebNQKXe/0kPivWokHWwXlDB7S7mBZzhaAPidZvnuIhalE2qmTypDwHy22FyqV58T8MGGMchcASDi/QXI6kcdpJzPXSeU9o+NC68QDlOIrMVxKFeE7w7PvVmAaxEo0YwmuAzzKy9QpdlK0aab/xEi8V4iXj4hGepqAvHkXIQd+r3FNeiLfllkb61p6WTjr5urcmDQMR94/wYoilpG5OlybHdbhsYHvIzYoLrC7fzl630gcO6t4nM24vdB6Ymg9BVpEgKRAxSbE62Tqacxqnz9AcmgItb48NiR/He3n3ydGjPYuKk/ihZMgEwAEZvSlNxYONSbYrIGDtOY+8Nbt6KiH3l06wjZW8tcmFeVlWv+tWotnTY9IqlAfvNVTjtsobqtQnvsiDjdEVtNy/s2ci5TH+NdZluca2OVEr91Wayxh70kpM6ib4UGbfdmGgCo74gtKvKSJU0rTHakQ5L9JlaSDD5FamBRyI0qfL43Ad9qOUZ8DaffDCyuaVyuqk7cz9HwmEmvWU3VQ+5t06n/5kRDXttcw8w+3qClEEdGo1KeENcnXCB32dQe3tDTFpuAIMLqwXs6FhpawfZ5kPYvLPczGWaqftIs/RXJ/EltGc0ugw2dmTLpoQhCqrcKEBDoYVk0LDZKsnzitOGdi9mOWse7Se8798ib1UsHFUjGzISEt6upestxOeupSTOh0v4+AjXbDzRUyogHww3V+Bqg71bkcMxtB+WM+pn1XNbVTyl9NR040nhP7KEf6e9ruXAtmrBC2ah5cFEpLIot77VFZ9ilLuitSz+7T8n1yAh1IEG6xxXxninAZIzi2qGbH69O5RSpOJuJTv17zTLJQIIc781JwQ2TTwTGnx5wZLbffhCasowJKd2EVcyMJyhz6ru0PvXWJ4hUdkARJs3Xu8dus9a86N8Xk6aAPzBDqzYb1vyFIfBxP0oO8xFHgd30Cgmz8UrSE3qeWRrF8ftrI6xQnFjHBGWD/JWSvd6YMcQED0aVuQkuNW9ST/DzQThPzRfPUoiL10yAmV7Ytu4fR3x2sF0Yfi87YhHFuCMpV/DsqxmUizyiJuD938eRcH8hzR/VO53Qo3UIsqOLcyXtTv6THjSlTopQ+JOLOnHm1w8dzYbLN44OG44rRsbihMUQp+wUZ6bsI8rrOnm9WErzkbQFbrfAINdoCiNa6cimYIjvvnMTaFWNymqY1vZxGztQiMiHiHYwTfwHTXrb9j0uPM=|09J28iXv9oWzYtzK2LBT6Yht4IT4MijEkk0fwFdrVQ4=";

    fn make_mock_upgrade_token() -> V2UpgradeToken {
        let key_store = KeyStore::<KeySlotIds>::default();
        let mut ctx = key_store.context_mut();
        let v1_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let v2_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        V2UpgradeToken::create(v1_id, v2_id, &ctx).unwrap()
    }

    fn register_in_memory_bridge(client: &Client) {
        client
            .km_state_bridge()
            .register_bridge(Box::new(InMemoryStateBridge::default()));
    }

    /// Make an XAES-256-GCM user key until normal V2 account initialization supports it.
    fn make_xaes_user_key(client: &Client) -> SymmetricCryptoKey {
        let mut ctx = client.internal.get_key_store().context_mut();
        let local_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        #[allow(deprecated)]
        let user_key = ctx
            .dangerous_get_symmetric_key(local_key_id)
            .unwrap()
            .clone();
        ctx.persist_symmetric_key(local_key_id, SymmetricKeySlotId::User)
            .unwrap();
        user_key
    }

    /// Assert that the client's active user key is V2 and matches `expected_v2_key`.
    fn assert_active_user_key_is_v2(client: &Client, expected_v2_key: &SymmetricCryptoKey) {
        let key_store = client.internal.get_key_store();
        let ctx = key_store.context();
        let algorithm = ctx
            .get_symmetric_key_algorithm(SymmetricKeySlotId::User)
            .unwrap();
        assert!(
            matches!(
                algorithm,
                SymmetricKeyAlgorithm::XChaCha20Poly1305 | SymmetricKeyAlgorithm::XAes256Gcm
            ),
            "user-slot algorithm must be V2 after upgrade"
        );

        #[allow(deprecated)]
        let user_key = ctx
            .dangerous_get_symmetric_key(SymmetricKeySlotId::User)
            .unwrap();
        assert_eq!(user_key, expected_v2_key);
    }

    /// V2 wrapped state from the test vectors. Wrapped under the V2 test user
    /// key, so it only decrypts cleanly when paired with that key.
    fn test_vector_v2_account_state() -> WrappedAccountCryptographicState {
        WrappedAccountCryptographicState::V2 {
            private_key: TEST_VECTOR_PRIVATE_KEY_V2.parse().unwrap(),
            signing_key: TEST_VECTOR_SIGNING_KEY_V2.parse().unwrap(),
            security_state: TEST_VECTOR_SECURITY_STATE_V2.parse().unwrap(),
            signed_public_key: Some(TEST_VECTOR_SIGNED_PUBLIC_KEY_V2.parse().unwrap()),
        }
    }

    fn test_vector_v1_account_state() -> WrappedAccountCryptographicState {
        WrappedAccountCryptographicState::V1 {
            private_key: TEST_VECTOR_PRIVATE_KEY_V1.parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn reinit_user_crypto_returns_not_unlocked_when_locked() {
        let client = Client::new_test(None);
        register_in_memory_bridge(&client);

        let result = reinit_user_crypto(
            &client,
            ReinitUserCryptoRequest {
                account_cryptographic_state: test_vector_v2_account_state(),
                upgrade_token: make_mock_upgrade_token(),
            },
        )
        .await;

        assert!(
            matches!(result, Err(ReinitUserCryptoError::NotUnlocked)),
            "reinit on a locked SDK must return NotUnlocked, got {result:?}"
        );
    }

    #[tokio::test]
    async fn reinit_user_crypto_is_noop_when_active_user_is_already_v2() {
        let client = Client::init_test_account(test_bitwarden_com_account_v2()).await;
        register_in_memory_bridge(&client);

        let result = reinit_user_crypto(
            &client,
            ReinitUserCryptoRequest {
                account_cryptographic_state: test_vector_v2_account_state(),
                upgrade_token: make_mock_upgrade_token(),
            },
        )
        .await;

        assert!(
            result.is_ok(),
            "reinit on an already-V2 user must be a no-op and return Ok, got {result:?}"
        );

        let expected_v2_key =
            SymmetricCryptoKey::try_from(TEST_VECTOR_USER_KEY_V2_B64.to_string()).unwrap();
        assert_active_user_key_is_v2(&client, &expected_v2_key);

        let upgrade_token = client.internal.state_bridge.get_v2_upgrade_token().await;
        assert!(
            upgrade_token.is_none(),
            "reinit on an already-V2 user must not set the upgrade token"
        );
    }

    #[tokio::test]
    async fn reinit_user_crypto_is_noop_when_active_user_key_is_xaes256gcm() {
        let client = Client::new_test(None);
        // TODO: Use normal V2 test-account initialization once it supports XAES-256-GCM.
        let expected_user_key = make_xaes_user_key(&client);
        register_in_memory_bridge(&client);

        let result = reinit_user_crypto(
            &client,
            ReinitUserCryptoRequest {
                account_cryptographic_state: test_vector_v2_account_state(),
                upgrade_token: make_mock_upgrade_token(),
            },
        )
        .await;

        assert!(
            result.is_ok(),
            "reinit with an XAES-256-GCM user key must be a no-op and return Ok, got {result:?}"
        );
        assert_active_user_key_is_v2(&client, &expected_user_key);

        let upgrade_token = client.internal.state_bridge.get_v2_upgrade_token().await;
        assert!(
            upgrade_token.is_none(),
            "reinit on an already-V2 user must not set the upgrade token"
        );
    }

    #[tokio::test]
    async fn reinit_user_crypto_upgrades_v1_to_v2_with_token() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        register_in_memory_bridge(&client);

        // Build a V2 user key, install it into a temporary local slot, and
        // create an upgrade token linking the active V1 user key to it.
        let expected_v2_key =
            SymmetricCryptoKey::try_from(TEST_VECTOR_USER_KEY_V2_B64.to_string()).unwrap();
        let upgrade_token = {
            let mut ctx = client.internal.get_key_store().context_mut();
            let v2_key_id = ctx.add_local_symmetric_key(expected_v2_key.clone());
            V2UpgradeToken::create(SymmetricKeySlotId::User, v2_key_id, &ctx).unwrap()
        };

        reinit_user_crypto(
            &client,
            ReinitUserCryptoRequest {
                account_cryptographic_state: test_vector_v2_account_state(),
                upgrade_token: upgrade_token.clone(),
            },
        )
        .await
        .expect("V1→V2 reinit with a valid upgrade token should succeed");

        assert_active_user_key_is_v2(&client, &expected_v2_key);

        assert_eq!(
            client.internal.get_security_version(),
            2,
            "security version must reflect the V2 state"
        );

        {
            let key_store = client.internal.get_key_store();
            let ctx = key_store.context();
            assert!(
                ctx.has_signing_key(SigningKeySlotId::UserSigningKey),
                "user signing key must be set after V1→V2 upgrade"
            );
            assert!(
                ctx.has_private_key(PrivateKeySlotId::UserPrivateKey),
                "user private key must be set after V1→V2 upgrade"
            );
        }

        let stored_token = client
            .internal
            .state_bridge
            .get_v2_upgrade_token()
            .await
            .expect("the upgrade token must be set on the state bridge after reinit");
        assert_eq!(
            stored_token.wrapped_user_key_1,
            upgrade_token.wrapped_user_key_1
        );
        assert_eq!(
            stored_token.wrapped_user_key_2,
            upgrade_token.wrapped_user_key_2
        );
    }

    #[tokio::test]
    async fn reinit_user_crypto_called_twice_with_same_payload_is_noop() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        register_in_memory_bridge(&client);

        let expected_v2_key =
            SymmetricCryptoKey::try_from(TEST_VECTOR_USER_KEY_V2_B64.to_string()).unwrap();
        let upgrade_token = {
            let mut ctx = client.internal.get_key_store().context_mut();
            let v2_key_id = ctx.add_local_symmetric_key(expected_v2_key.clone());
            V2UpgradeToken::create(SymmetricKeySlotId::User, v2_key_id, &ctx).unwrap()
        };

        let request = || ReinitUserCryptoRequest {
            account_cryptographic_state: test_vector_v2_account_state(),
            upgrade_token: upgrade_token.clone(),
        };

        // First call performs the V1→V2 upgrade.
        reinit_user_crypto(&client, request())
            .await
            .expect("V1→V2 reinit with a valid upgrade token should succeed");
        assert_active_user_key_is_v2(&client, &expected_v2_key);

        // Second call with the same payload is a no-op: the active user key is
        // already V2, so the token is never re-applied.
        reinit_user_crypto(&client, request())
            .await
            .expect("re-applying the same upgrade after success should be a no-op");
        assert_active_user_key_is_v2(&client, &expected_v2_key);
    }

    #[tokio::test]
    async fn reinit_user_crypto_invalid_upgrade_token_returns_error() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        register_in_memory_bridge(&client);

        // Token built with a different V1 key — unwrapping with the client's
        // V1 key will fail.
        let mismatched_token = make_mock_upgrade_token();

        let result = reinit_user_crypto(
            &client,
            ReinitUserCryptoRequest {
                account_cryptographic_state: test_vector_v2_account_state(),
                upgrade_token: mismatched_token,
            },
        )
        .await;

        assert!(
            matches!(result, Err(ReinitUserCryptoError::InvalidUpgradeToken)),
            "mismatched upgrade token must return InvalidUpgradeToken, got {result:?}"
        );
    }

    #[tokio::test]
    async fn reinit_user_crypto_returns_crypto_initialization_on_key_mismatch() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        register_in_memory_bridge(&client);

        // Build an upgrade token whose V2 target is a fresh random key (not the
        // test-vector key). `unwrap_v2` only checks internal token consistency,
        // so it succeeds, but the resolved V2 key cannot decrypt the
        // test-vector account state.
        let upgrade_token = {
            let mut ctx = client.internal.get_key_store().context_mut();
            let v2_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
            V2UpgradeToken::create(SymmetricKeySlotId::User, v2_key_id, &ctx).unwrap()
        };

        let result = reinit_user_crypto(
            &client,
            ReinitUserCryptoRequest {
                account_cryptographic_state: test_vector_v2_account_state(),
                upgrade_token,
            },
        )
        .await;

        assert!(
            matches!(result, Err(ReinitUserCryptoError::CryptoInitialization)),
            "a V2 key that cannot decrypt the account state must return CryptoInitialization, got {result:?}"
        );

        // `set_to_context` resolves the V2 key into a local slot and fails
        // before it ever rewrites the User slot, so the original V1 user key is
        // left intact. The active session remains usable on failure.
        let key_store = client.internal.get_key_store();
        let ctx = key_store.context();
        assert!(
            ctx.has_symmetric_key(SymmetricKeySlotId::User),
            "the original V1 user key must remain in the User slot on failure"
        );
        assert_eq!(
            ctx.get_symmetric_key_algorithm(SymmetricKeySlotId::User)
                .unwrap(),
            SymmetricKeyAlgorithm::Aes256CbcHmac,
            "the User slot must still hold the original V1 key on failure"
        );
    }

    #[tokio::test]
    async fn reinit_user_crypto_returns_invalid_account_state_on_v1_request() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let result = reinit_user_crypto(
            &client,
            ReinitUserCryptoRequest {
                account_cryptographic_state: test_vector_v1_account_state(),
                upgrade_token: make_mock_upgrade_token(),
            },
        )
        .await;

        assert!(
            matches!(
                result,
                Err(ReinitUserCryptoError::InvalidAccountCryptographicState)
            ),
            "a V1 account state must return InvalidAccountState, got {result:?}"
        );
    }

    #[tokio::test]
    async fn reinit_user_crypto_returns_state_bridge_not_registered_when_no_bridge() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let result = reinit_user_crypto(
            &client,
            ReinitUserCryptoRequest {
                account_cryptographic_state: test_vector_v2_account_state(),
                upgrade_token: make_mock_upgrade_token(),
            },
        )
        .await;

        assert!(
            matches!(result, Err(ReinitUserCryptoError::StateBridgeNotRegistered)),
            "reinit without a registered state bridge must return StateBridgeNotRegistered, got {result:?}"
        );
    }

    #[tokio::test]
    async fn reinit_user_crypto_v1_v2_upgrade_rewraps_local_user_data_key() {
        use crate::key_management::LocalUserDataKeyState;

        // Bootstrap a V1 client to materialize a V1-wrapped LocalUserDataKey state.
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let user_id = UserId::new(uuid::uuid!("060000fb-0922-4dd3-b170-6e15cb5df8c8"));
        register_in_memory_bridge(&client);

        // The V1 init plants a V1-wrapped local user data key in state.
        let v1_user_data_key = client
            .platform()
            .state()
            .get::<LocalUserDataKeyState>()
            .unwrap()
            .get(user_id)
            .await
            .unwrap()
            .expect("V1 init should plant a LocalUserDataKey state");
        assert!(
            matches!(
                v1_user_data_key.wrapped_key,
                EncString::Aes256Cbc_HmacSha256_B64 { .. }
            ),
            "initial local user data key should be V1-wrapped"
        );

        let v2_key = SymmetricCryptoKey::try_from(TEST_VECTOR_USER_KEY_V2_B64.to_string()).unwrap();
        let upgrade_token = {
            let mut ctx = client.internal.get_key_store().context_mut();
            let v2_key_id = ctx.add_local_symmetric_key(v2_key.clone());
            V2UpgradeToken::create(SymmetricKeySlotId::User, v2_key_id, &ctx).unwrap()
        };

        reinit_user_crypto(
            &client,
            ReinitUserCryptoRequest {
                account_cryptographic_state: test_vector_v2_account_state(),
                upgrade_token,
            },
        )
        .await
        .expect("V1→V2 reinit with a valid upgrade token should succeed");

        // The persisted wrapped local user data key must now be sealed with the V2 user key.
        let rewrapped_state = client
            .platform()
            .state()
            .get::<LocalUserDataKeyState>()
            .unwrap()
            .get(user_id)
            .await
            .unwrap()
            .expect("LocalUserDataKey state must remain present");
        assert!(
            matches!(
                rewrapped_state.wrapped_key,
                EncString::Cose_Encrypt0_B64 { .. }
            ),
            "rewrapped key should be sealed with the V2 user key"
        );
        assert_ne!(rewrapped_state.wrapped_key, v1_user_data_key.wrapped_key);
    }
}
