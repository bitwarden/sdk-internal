import type { PasswordManagerClient } from "@bitwarden/sdk-internal";

/**
 * Whether the rotation issues a V2 upgrade token.
 *
 * Only a V1 to V2 rotation produces one, and it is what lets a session already unlocked on the old
 * key re-initialize onto the new one instead of unlocking again.
 */
export type UpgradeTokenAction = "CreateIfNeeded" | "Skip";

/** Whether a rotation upgrades a V1 user key to V2, as the server's feature flag says. */
export type ForceUpgradeV2 = "on" | "off";

const FORCE_UPGRADE_V2_FLAG = "force-upgrade-v2-encryption";

/** Loads the `force-upgrade-v2-encryption` flag into the client, as a client does from `/config`. */
export async function setForceUpgradeV2(
  sdk: PasswordManagerClient,
  forceUpgradeV2: ForceUpgradeV2,
): Promise<void> {
  await sdk.platform().load_flags(new Map([[FORCE_UPGRADE_V2_FLAG, forceUpgradeV2 === "on"]]));
}

/** Rotates with the account's password, either upgrading to V2 or carrying V2 forward. */
export async function rotateByPassword(
  sdk: PasswordManagerClient,
  password: string,
  upgradeTokenAction: UpgradeTokenAction,
  forceUpgradeV2: ForceUpgradeV2 = "on",
): Promise<void> {
  await setForceUpgradeV2(sdk, forceUpgradeV2);
  await sdk.user_crypto_management().rotate_user_keys({
    key_rotation_method: { Password: { password } },
    trusted_emergency_access_public_keys: [],
    trusted_organization_public_keys: [],
    upgrade_token_action: upgradeTokenAction,
  });
}

/** Changes the account's password and rotates its user key in one request. */
export async function changePasswordAndRotate(
  sdk: PasswordManagerClient,
  oldPassword: string,
  newPassword: string,
  forceUpgradeV2: ForceUpgradeV2,
): Promise<void> {
  await setForceUpgradeV2(sdk, forceUpgradeV2);
  await sdk.user_crypto_management().password_change_and_rotate_user_keys({
    old_password: oldPassword,
    password: newPassword,
    hint: undefined,
    trusted_emergency_access_public_keys: [],
    trusted_organization_public_keys: [],
  });
}
