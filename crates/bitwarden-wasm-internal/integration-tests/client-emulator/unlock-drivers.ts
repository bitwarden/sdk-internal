// The device-side hooks shared unlock and biometric unlock call into, wired to a real client.
//
// The SDK owns the protocol; a driver is where it reaches back out to lock or unlock the app. These
// implementations do exactly that against a `ClientEmulator`, so a propagated key has to actually
// open that client's vault for a test to pass.

import {
  BiometricsStatus,
  type BiometricsUnlock,
  type SharedUnlockDriver,
  type SymmetricKey,
  type UserId,
} from "@bitwarden/sdk-internal";

import { asUserId } from "../tests/type-assertion-helpers";

import type { ClientEmulator } from "./client-emulator";
import { WEB_ORIGIN } from "./transport";

/** What `discover_leader` reads to place a peer in the hierarchy. Desktop has no leader. */
export type ClientName = "desktop" | "browser" | "web" | "cli";

export interface SharedUnlockDriverOptions {
  /**
   * The vault url reported for every user, which is what scopes sharing with a web peer.
   *
   * Defaults to {@link WEB_ORIGIN} so a web peer on the bus is origin-valid, leaving the
   * destination list as the only thing that decides whether it is synced to.
   */
  vaultUrl?: string;
}

export interface EmulatedSharedUnlockDriver {
  driver: SharedUnlockDriver;
  /** Every `suppress_vault_timeout` duration this client was asked for, in milliseconds. */
  suppressions: number[];
}

/** A shared-unlock driver that locks and unlocks `client` for real. */
export function makeSharedUnlockDriver(
  client: ClientEmulator,
  clientName: ClientName,
  options: SharedUnlockDriverOptions = {},
): EmulatedSharedUnlockDriver {
  const vaultUrl = options.vaultUrl ?? WEB_ORIGIN;
  const suppressions: number[] = [];

  return {
    driver: {
      lock_user: async () => client.lock(),
      unlock_user: async (_userId: UserId, userKey: SymmetricKey) =>
        client.unlockWithUserKey(userKey),
      // The one account this client has synced down. A user the driver does not list is one the
      // peer refuses to advertise or apply, so this is what scopes the protocol to real accounts.
      list_users: async () => [asUserId(client.local.account.userId)],
      suppress_vault_timeout: async (_userId: UserId, duration: number) => {
        suppressions.push(duration);
      },
      get_client_name: async () => clientName,
      get_vault_url: async () => vaultUrl,
    },
    suppressions,
  };
}

export interface BiometricsDriverOptions {
  status?: BiometricsStatus;
  /** Whether the user verification prompt succeeds. */
  uvResult?: boolean;
  /**
   * Whether the biometric prompt is completed. `false` stands for a canceled or failed unlock,
   * which hands back no key.
   */
  unlockSucceeds?: boolean;
}

/**
 * A biometrics driver backed by an unlocked client.
 *
 * A real desktop app releases the user key its keychain holds; this releases the key the unlocked
 * emulator holds, which is the same key the requesting client must end up able to decrypt with.
 */
export function makeBiometricsDriver(
  client: ClientEmulator,
  options: BiometricsDriverOptions = {},
): BiometricsUnlock {
  const { status = BiometricsStatus.Available, uvResult = true, unlockSucceeds = true } = options;

  return {
    get_biometrics_status: async () => status,
    unlock_biometrics: async () => (unlockSucceeds ? await client.userKey() : undefined),
    authenticate_biometrics: async () => uvResult,
  };
}
