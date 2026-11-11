import type { PasswordManagerClient } from "@bitwarden/sdk-internal";

/**
 * Whether the rotation issues a V2 upgrade token.
 *
 * Only a V1 to V2 rotation produces one, and it is what lets a session already unlocked on the old
 * key re-initialize onto the new one instead of unlocking again.
 */
export type UpgradeTokenAction = "CreateIfNeeded" | "Skip";

/**
 * Which user key version a rotation produces. Clients set it from the
 * `force-upgrade-v2-encryption` feature flag.
 */
export type UserKeyUpgrade = "KeepVersion" | "UpgradeToV2";

/** Rotates with the account's password, either upgrading to V2 or carrying V2 forward. */
export async function rotateByPassword(
  sdk: PasswordManagerClient,
  password: string,
  upgradeTokenAction: UpgradeTokenAction,
  userKeyUpgrade: UserKeyUpgrade = "UpgradeToV2",
): Promise<void> {
  await sdk.user_crypto_management().rotate_user_keys({
    key_rotation_method: { Password: { password } },
    trusted_emergency_access_public_keys: [],
    trusted_organization_public_keys: [],
    upgrade_token_action: upgradeTokenAction,
    user_key_upgrade: userKeyUpgrade,
  });
}

/** Changes the account's password and rotates its user key in one request. */
export async function changePasswordAndRotate(
  sdk: PasswordManagerClient,
  oldPassword: string,
  newPassword: string,
  userKeyUpgrade: UserKeyUpgrade,
): Promise<void> {
  await sdk.user_crypto_management().password_change_and_rotate_user_keys({
    old_password: oldPassword,
    password: newPassword,
    hint: undefined,
    trusted_emergency_access_public_keys: [],
    trusted_organization_public_keys: [],
    user_key_upgrade: userKeyUpgrade,
  });
}
