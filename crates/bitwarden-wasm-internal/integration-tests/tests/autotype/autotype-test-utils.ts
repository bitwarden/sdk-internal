import {
  AutotypeDriver,
  AutotypeRunningApp,
  IpcClient,
  autotypeRegisterHandlers,
  init_sdk,
} from "@bitwarden/sdk-internal";

import { makeMockTransportPair } from "../utils";

/**
 * Per-channel behavior for the mock driver. Each channel is varied independently so a test can
 * make one of them fail without disturbing the other.
 */
export interface MockAutotypeDriverOptions {
  setEnabled: (enabled: boolean) => Promise<boolean>;
  setKeyboardShortcut: (shortcut: string[]) => Promise<boolean>;
  // Typed loosely so a test can return a malformed payload, which is exactly what the SDK's
  // deserialization is being asked to survive.
  listRunningApps: () => Promise<unknown>;
}

/**
 * Recorded calls per channel. `list_running_apps` takes no arguments, so a count is all there is
 * to record for it.
 */
export interface MockAutotypeDriverCalls {
  enabledCalls: boolean[];
  shortcutCalls: string[][];
  listRunningAppsCalls: number;
}

/**
 * In-memory implementation of the `AutotypeDriver` JS interface. Records what it was asked to do
 * per channel, and reports whether it applied the change — which the tests vary independently of
 * the request, to cover a driver that fails.
 */
export function makeMockAutotypeDriver(
  options: Partial<MockAutotypeDriverOptions> = {},
): AutotypeDriver & MockAutotypeDriverCalls {
  const {
    setEnabled = async () => true,
    setKeyboardShortcut = async () => true,
    listRunningApps = async () => [],
  } = options;

  const enabledCalls: boolean[] = [];
  const shortcutCalls: string[][] = [];
  // A counter rather than an array, so it needs a getter — a plain number property would be
  // snapshotted at construction and never update.
  let listRunningAppsCalls = 0;

  return {
    enabledCalls,
    shortcutCalls,
    get listRunningAppsCalls() {
      return listRunningAppsCalls;
    },
    set_autotype_enabled: async (enabled: boolean) => {
      enabledCalls.push(enabled);
      return setEnabled(enabled);
    },
    set_autotype_keyboard_shortcut: async (shortcut: string[]) => {
      shortcutCalls.push(shortcut);
      return setKeyboardShortcut(shortcut);
    },
    list_running_apps: async () => {
      listRunningAppsCalls += 1;
      return (await listRunningApps()) as AutotypeRunningApp[];
    },
  };
}

/**
 * Builds the desktop pairing the real app uses: a main-process client that owns the global
 * shortcut and a renderer-process client that drives it, over paired in-memory transports.
 *
 * Only `main` registers the handlers, matching the one-directional channels — the renderer sends,
 * main applies.
 */
export async function setupClientPair(driver: AutotypeDriver = makeMockAutotypeDriver()) {
  init_sdk();

  const [mainBackend, rendererBackend] = makeMockTransportPair();
  const main = IpcClient.newWithSdkInMemorySessions(mainBackend);
  const renderer = IpcClient.newWithSdkInMemorySessions(rendererBackend);

  await main.start();
  await renderer.start();

  await autotypeRegisterHandlers(main, driver);

  return { main, renderer };
}
