// Shared setup for the tests that run several clients on one device.
//
// Each device is a `ClientEmulator` synced from the same server emulator and attached to the same
// `IpcBus`, so the only thing under test is what the clients say to each other.

import type { SharedUnlockDriver, SymmetricKey, UserId } from "@bitwarden/sdk-internal";

import type { ClientEmulator } from "../../client-emulator/client-emulator";
import type { IpcBus } from "../../client-emulator/transport";
import { makeSharedUnlockDriver, type ClientName } from "../../client-emulator/unlock-drivers";
import type { TestHarness } from "../../test-harness";
import { asUserId } from "../type-assertion-helpers";

import type { Source } from "@bitwarden/sdk-internal";

/** Matches `SYNC_INTERVAL` in `bitwarden-shared-unlock/src/lib.rs`. */
export const SYNC_INTERVAL_MS = 5000;

/** A real KDF derivation per unlock, plus a sync interval or two of waiting. */
export const PEER_TIMEOUT = 60_000;

/** One client on the emulated device: its state, its transport, and its device hooks. */
export interface Device {
  client: ClientEmulator;
  driver: SharedUnlockDriver;
  /** Every `suppress_vault_timeout` duration this client was asked for, in milliseconds. */
  suppressions: number[];
  userId: UserId;
}

/** Logs a client in, puts it on `bus`, and builds its shared-unlock driver. Leaves it locked. */
export async function joinDevice(
  harness: TestHarness,
  bus: IpcBus,
  email: string,
  source: Source,
  clientName: ClientName,
): Promise<Device> {
  const client = harness.newClientEmulator();
  client.setIpcSource(source);
  await client.login(email);
  await client.attachIpc(bus);

  const { driver, suppressions } = makeSharedUnlockDriver(client, clientName);

  return { client, driver, suppressions, userId: asUserId(client.local.account.userId) };
}

/** Whether the client holds a user key, which is what separates unlocked from locked. */
export async function isUnlocked(client: ClientEmulator): Promise<boolean> {
  return (await userKeyOf(client)) !== undefined;
}

/** The user key the client holds, or `undefined` while it is locked. */
export async function userKeyOf(client: ClientEmulator): Promise<SymmetricKey | undefined> {
  return (await client.bridge.get_user_key()) ?? undefined;
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Polls until `condition` holds.
 *
 * Whether a sync lands in the first round trip or the next interval depends on where in the tick it
 * was reported, so the tests wait for an outcome rather than for a duration. `description` names
 * what never happened, since a bare timeout says nothing about which side stalled.
 */
export async function waitFor(
  condition: () => Promise<boolean>,
  description: string,
  timeoutMs = 30_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;

  for (;;) {
    if (await condition()) {
      return;
    }
    if (Date.now() >= deadline) {
      throw new Error(`timed out after ${timeoutMs}ms waiting for ${description}`);
    }

    await delay(25);
  }
}
