import type { PasswordManagerClient } from "@bitwarden/sdk-internal";

/**
 * Whether the rotation issues a V2 upgrade token.
 *
 * Only a V1 to V2 rotation produces one, and it is what lets a session already unlocked on the old
 * key re-initialize onto the new one instead of unlocking again.
 */
export type UpgradeTokenAction = "CreateIfNeeded" | "Skip";

/** Rotates with the account's password, either upgrading to V2 or carrying V2 forward. */
export async function rotateByPassword(
  sdk: PasswordManagerClient,
  password: string,
  upgradeTokenAction: UpgradeTokenAction,
): Promise<void> {
  await sdk.user_crypto_management().rotate_user_keys({
    key_rotation_method: { Password: { password } },
    trusted_emergency_access_public_keys: [],
    trusted_organization_public_keys: [],
    upgrade_token_action: upgradeTokenAction,
  });
}
