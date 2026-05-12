use bitwarden_crypto::EncString;
use tracing::info;

use crate::{
    Client, UserId,
    key_management::{self, SymmetricKeySlotId, local_user_data_key::WrappedLocalUserDataKey},
};

pub(crate) struct InitLocalUserDataKeyError;

/// Stores [`WrappedLocalUserDataKey`] in state if one does not already exist.
pub(crate) async fn initialize_local_user_data_key_into_state(
    client: &Client,
    user_id: UserId,
) -> Result<(), InitLocalUserDataKeyError> {
    let repo = client
        .platform()
        .state()
        .get::<key_management::LocalUserDataKeyState>()
        .map_err(|_| InitLocalUserDataKeyError)?;

    // Idempotent: only set if no key is present yet.
    if let Ok(Some(_)) = repo.get(user_id).await {
        info!("WrappedLocalUserDataKey already exists in state, skipping");
        return Ok(());
    }

    info!("Setting WrappedLocalUserDataKey to state from user key");
    let wrapped_local_user_data_key = {
        let key_store = client.internal.get_key_store();
        let mut ctx = key_store.context();
        WrappedLocalUserDataKey::from_context_user_key(&mut ctx)
            .map_err(|_| InitLocalUserDataKeyError)?
    };

    repo.set(user_id, wrapped_local_user_data_key.into())
        .await
        .map_err(|_| InitLocalUserDataKeyError)
}

#[derive(Debug)]
pub(crate) struct MigrateLocalUserDataKeyForUserKeyUpgradeError;

/// Re-wraps a persisted [`WrappedLocalUserDataKey`] with the current user key after a V1→V2
/// user-key upgrade, preserving the inner-key plaintext so local data encrypted before the
/// upgrade remains decryptable. No-ops when migration is unnecessary or impossible.
pub(crate) async fn migrate_local_user_data_key_for_user_key_upgrade(
    client: &Client,
    user_id: UserId,
) -> Result<(), MigrateLocalUserDataKeyForUserKeyUpgradeError> {
    // Remove when all host clients implement the state bridge - https://bitwarden.atlassian.net/browse/PM-37189
    if !client.internal.state_bridge.is_registered() {
        info!("No state bridge registered, skipping WrappedLocalUserDataKey migration");
        return Ok(());
    }

    let Some(token) = client.internal.state_bridge.get_v2_upgrade_token().await else {
        info!(
            "No V2 upgrade token available from state bridge, skipping WrappedLocalUserDataKey migration"
        );
        return Ok(());
    };

    let repo = client
        .platform()
        .state()
        .get::<key_management::LocalUserDataKeyState>()
        .map_err(|_| MigrateLocalUserDataKeyForUserKeyUpgradeError)?;
    let Some(state) = repo
        .get(user_id)
        .await
        .map_err(|_| MigrateLocalUserDataKeyForUserKeyUpgradeError)?
    else {
        return Ok(());
    };
    if !matches!(
        state.wrapped_key,
        EncString::Aes256Cbc_HmacSha256_B64 { .. }
    ) {
        info!("WrappedLocalUserDataKey is not a V1 wrapped key, skipping migration");
        return Ok(());
    }

    let rewrapped = {
        let mut ctx = client.internal.get_key_store().context_mut();
        let Ok(v1_user_key_id) = token.unwrap_v1(SymmetricKeySlotId::User, &mut ctx) else {
            info!(
                "Upgrade token does not apply to current user key, skipping WrappedLocalUserDataKey migration"
            );
            return Ok(());
        };

        let wrapped = WrappedLocalUserDataKey(state.wrapped_key);
        wrapped
            .rewrap_with_user_key(v1_user_key_id, &mut ctx)
            .map_err(|_| MigrateLocalUserDataKeyForUserKeyUpgradeError)?
    };

    info!("Rewrapping WrappedLocalUserDataKey with current user key");
    repo.set(user_id, rewrapped.into())
        .await
        .map_err(|_| MigrateLocalUserDataKeyForUserKeyUpgradeError)
}

pub(crate) struct UnableToGetError;

/// Retrieves the [`WrappedLocalUserDataKey`] from state.
pub(crate) async fn get_local_user_data_key_from_state(
    client: &Client,
    user_id: UserId,
) -> Result<WrappedLocalUserDataKey, UnableToGetError> {
    info!("Getting the WrappedLocalUserDataKey from state");
    let user_local_data_key_state = client
        .platform()
        .state()
        .get::<key_management::LocalUserDataKeyState>()
        .map_err(|_| UnableToGetError)?
        .get(user_id)
        .await
        .map_err(|_| UnableToGetError)?
        .ok_or(UnableToGetError)?;

    Ok(WrappedLocalUserDataKey(
        user_local_data_key_state.wrapped_key,
    ))
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{KeyStoreContext, SymmetricCryptoKey};
    use bitwarden_encoding::B64;
    use uuid::uuid;

    use super::*;
    use crate::{
        Client, UserId,
        key_management::{
            KeySlotIds, LocalUserDataKeyState, SymmetricKeySlotId, V2UpgradeToken,
            local_user_data_key::WrappedLocalUserDataKey,
            state_bridge::test_support::InMemoryStateBridge,
        },
    };

    const V1_USER_KEY: &str =
        "9j9Ruji/tMHlLZ311I5xJugi4pMLbS7WxApM4yTa4is7c1mEgt4ov8fR6/zA9VvgP+wXfx79HG0C+89xMlqksw==";
    fn load_v1_user_key(ctx: &mut KeyStoreContext<KeySlotIds>) -> SymmetricKeySlotId {
        let key = SymmetricCryptoKey::try_from(B64::try_from(V1_USER_KEY).unwrap()).unwrap();
        ctx.add_local_symmetric_key(key)
    }
    const V2_USER_KEY: &str = "pQEEAlCg4GEL17wqaWbSzi7WdH1kAzoAARFvBIQDBAUGIFgg1opRU0oX0Rje8I0ufEOx7Xv6NIoOCSAb1ex312/xDqkB";
    fn load_v2_user_key(ctx: &mut KeyStoreContext<KeySlotIds>) -> SymmetricKeySlotId {
        let key = SymmetricCryptoKey::try_from(B64::try_from(V2_USER_KEY).unwrap()).unwrap();
        ctx.add_local_symmetric_key(key)
    }

    #[tokio::test]
    async fn test_migrate_noop_when_state_bridge_not_registered() {
        let client = test_client(ClientVariants::WithoutStateBridge);
        initialize_state(
            &client,
            UserCryptographyVersion::V1,
            UpgradeTokenVariant::Present,
            LocalUserKeyVariant::PreUpgrade,
        )
        .await;
        run_migration_and_assert_noop(&client).await;
    }

    #[tokio::test]
    async fn test_migrate_noop_when_no_v2_upgrade_token() {
        let client = test_client(ClientVariants::WithStateBridge);
        initialize_state(
            &client,
            UserCryptographyVersion::V1,
            UpgradeTokenVariant::NotPresent,
            LocalUserKeyVariant::PreUpgrade,
        )
        .await;
        run_migration_and_assert_noop(&client).await;
    }

    #[tokio::test]
    async fn test_migrate_noop_when_no_wrapped_key() {
        let client = test_client(ClientVariants::WithStateBridge);
        initialize_state(
            &client,
            UserCryptographyVersion::V1,
            UpgradeTokenVariant::Present,
            LocalUserKeyVariant::NotPresent,
        )
        .await;
        run_migration_and_assert_noop(&client).await;
    }

    #[tokio::test]
    async fn test_migrate_noop_when_wrapped_key_is_not_v1() {
        let client = test_client(ClientVariants::WithStateBridge);
        initialize_state(
            &client,
            UserCryptographyVersion::V2,
            UpgradeTokenVariant::Present,
            LocalUserKeyVariant::PostUpgrade,
        )
        .await;
        run_migration_and_assert_noop(&client).await;
    }

    #[tokio::test]
    async fn test_migrate_happy_path_rewraps_and_preserves_payload() {
        let client = test_client(ClientVariants::WithStateBridge);
        initialize_state(
            &client,
            UserCryptographyVersion::V2,
            UpgradeTokenVariant::Present,
            LocalUserKeyVariant::PreUpgrade,
        )
        .await;
        let before = read_present_local_user_data_key(&client)
            .await
            .expect("LocalUserDataKeyState should be present after initialization");
        run_migration(&client).await;
        let after = read_present_local_user_data_key(&client)
            .await
            .expect("LocalUserDataKeyState should be present after migration");

        assert_local_user_data_key_is_correct(&client, (&before).into());
        assert!(matches!(
            before.wrapped_key,
            EncString::Aes256Cbc_HmacSha256_B64 { .. }
        ));
        assert_local_user_data_key_is_correct(&client, (&after).into());
        assert!(matches!(
            after.wrapped_key,
            EncString::Cose_Encrypt0_B64 { .. }
        ));
    }

    // Test helper functions

    fn test_user_id() -> UserId {
        UserId::new(uuid!("00000000-0000-0000-0000-000000000001"))
    }

    enum ClientVariants {
        WithStateBridge,
        WithoutStateBridge,
    }

    /// Builds a test client, optionally registering an in-memory state bridge.
    fn test_client(variant: ClientVariants) -> Client {
        let client = Client::new_test(None);
        if let ClientVariants::WithStateBridge = variant {
            client
                .km_state_bridge()
                .register_bridge(Box::new(InMemoryStateBridge::default()));
        }
        client
    }

    enum UserCryptographyVersion {
        V1,
        V2,
    }

    #[derive(PartialEq)]
    enum UpgradeTokenVariant {
        Present,
        NotPresent,
    }

    #[derive(PartialEq)]
    enum LocalUserKeyVariant {
        PreUpgrade,
        PostUpgrade,
        NotPresent,
    }

    /// Persists a freshly-generated user key into `SymmetricKeySlotId::User` and stores a
    /// `WrappedLocalUserDataKey` wrapped with it.
    async fn initialize_state(
        client: &Client,
        user_cryptography_version: UserCryptographyVersion,
        upgrade_token_variant: UpgradeTokenVariant,
        local_user_key_variant: LocalUserKeyVariant,
    ) {
        let (upgrade_token, wrapped_key) = {
            let mut ctx = client.internal.get_key_store().context_mut();
            let v1_user_key = load_v1_user_key(&mut ctx);
            ctx.persist_symmetric_key(v1_user_key, SymmetricKeySlotId::User)
                .expect("persisting V1 user key should succeed");

            // We start out with a v1 state, and the wrapped local user data key is a v1 key
            let mut wrapped_local_user_data_key =
                WrappedLocalUserDataKey::from_context_user_key(&mut ctx)
                    .expect("wrapping should succeed");
            if let LocalUserKeyVariant::PostUpgrade = local_user_key_variant {
                let v1_user_key = load_v1_user_key(&mut ctx);
                let v2_user_key = load_v2_user_key(&mut ctx);
                ctx.persist_symmetric_key(v2_user_key, SymmetricKeySlotId::User)
                    .expect("persisting V2 user key should succeed");
                wrapped_local_user_data_key = wrapped_local_user_data_key
                    .rewrap_with_user_key(v1_user_key, &mut ctx)
                    .expect("rewrap with V1 user key should succeed");
            }

            // Note: Persisting clears the key slots we are persisting from, so we have to reload
            // the keys
            let v1_user_key = load_v1_user_key(&mut ctx);
            let v2_user_key = load_v2_user_key(&mut ctx);

            let upgrade_token = V2UpgradeToken::create(v1_user_key, v2_user_key, &ctx)
                .expect("upgrade token creation should succeed");

            match user_cryptography_version {
                UserCryptographyVersion::V1 => {
                    ctx.persist_symmetric_key(v1_user_key, SymmetricKeySlotId::User)
                }
                UserCryptographyVersion::V2 => {
                    ctx.persist_symmetric_key(v2_user_key, SymmetricKeySlotId::User)
                }
            }
            .expect("persisting user key should succeed");

            (upgrade_token, wrapped_local_user_data_key)
        };

        if let UpgradeTokenVariant::Present = upgrade_token_variant
            && client.km_state_bridge().is_bridge_registered()
        {
            client
                .km_state_bridge()
                .set_v2_upgrade_token(&upgrade_token)
                .await;
        }

        if local_user_key_variant == LocalUserKeyVariant::PreUpgrade
            || local_user_key_variant == LocalUserKeyVariant::PostUpgrade
        {
            client
                .platform()
                .state()
                .get::<LocalUserDataKeyState>()
                .unwrap()
                .set(test_user_id(), wrapped_key.into())
                .await
                .unwrap();
        }
    }

    /// Reads the LocalUserDataKeyState for the test user, panicking if absent.
    async fn read_present_local_user_data_key(client: &Client) -> Option<LocalUserDataKeyState> {
        client
            .platform()
            .state()
            .get::<LocalUserDataKeyState>()
            .unwrap()
            .get(test_user_id())
            .await
            .expect("getting LocalUserDataKeyState from state should succeed")
    }

    async fn run_migration(client: &Client) {
        migrate_local_user_data_key_for_user_key_upgrade(client, test_user_id())
            .await
            .expect("migration should succeed")
    }

    /// Runs the migration and asserts that the wrapped key in state is unchanged.
    async fn run_migration_and_assert_noop(client: &Client) {
        let before = read_present_local_user_data_key(client).await;
        run_migration(client).await;
        let after = read_present_local_user_data_key(client).await;
        assert_eq!(after.map(|k| k.wrapped_key), before.map(|k| k.wrapped_key));
    }

    /// Asserts that the provided wrapped local user data key can be decrypted, and is the v1 test
    /// key
    fn assert_local_user_data_key_is_correct(ctx: &Client, wrapped_key: WrappedLocalUserDataKey) {
        let mut ctx = ctx.internal.get_key_store().context_mut();
        let v1_user_key = load_v1_user_key(&mut ctx);
        let v2_user_key = load_v2_user_key(&mut ctx);

        match wrapped_key.0 {
            EncString::Aes256Cbc_HmacSha256_B64 { .. } => {
                let local_user_data_key = ctx
                    .unwrap_symmetric_key(v1_user_key, &wrapped_key.0)
                    .expect("unwrapping with V1 user key should succeed");
                ctx.assert_symmetric_keys_equal(local_user_data_key, v1_user_key)
            }
            EncString::Cose_Encrypt0_B64 { .. } => {
                let local_user_data_key = ctx
                    .unwrap_symmetric_key(v2_user_key, &wrapped_key.0)
                    .expect("unwrapping with V2 user key should succeed");
                ctx.assert_symmetric_keys_equal(local_user_data_key, v1_user_key)
            }
            _ => panic!("unexpected encoding variant"),
        }
    }
}
