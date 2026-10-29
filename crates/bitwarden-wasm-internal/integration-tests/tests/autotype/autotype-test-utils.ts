import {
  AppMetadata,
  AutotypeCredentials,
  AutotypeDriver,
  AutotypeRenderDriver,
  AutotypeRunningApp,
  IpcClient,
  Source,
  init_sdk,
  registerAutotypeHandlers,
  registerAutotypeRenderHandlers,
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
 * Behavior for the mock render driver, the render process's side of the main → render
 * channels.
 */
export interface MockAutotypeRenderDriverOptions {
  // Typed loosely so a test can return malformed credentials, which is exactly what the SDK's
  // deserialization is being asked to survive.
  getCredentials: (app: AutotypeRunningApp, metadata: AppMetadata) => Promise<unknown>;
}

/** Recorded calls per main → render channel. */
export interface MockAutotypeRenderDriverCalls {
  getCredentialsCalls: { app: AutotypeRunningApp; metadata: AppMetadata }[];
}

/**
 * In-memory implementation of the `AutotypeRenderDriver` JS interface. Records what it was asked
 * to do, and returns what the per-channel behavior gives it. By default it finds no match.
 */
export function makeMockAutotypeRenderDriver(
  options: Partial<MockAutotypeRenderDriverOptions> = {},
): AutotypeRenderDriver & MockAutotypeRenderDriverCalls {
  const { getCredentials = async () => undefined } = options;

  const getCredentialsCalls: { app: AutotypeRunningApp; metadata: AppMetadata }[] = [];

  return {
    getCredentialsCalls,
    get_autotype_credentials: async (app: AutotypeRunningApp, metadata: AppMetadata) => {
      getCredentialsCalls.push({ app, metadata });
      return (await getCredentials(app, metadata)) as AutotypeCredentials | undefined;
    },
  };
}

/**
 * Builds the desktop pairing the real app uses: a main-process client that owns the global
 * shortcut and a renderer-process client that drives it, over paired in-memory transports.
 *
 * Only `main` registers handlers, matching the renderer → main channels — the renderer sends, main
 * applies. See `setupRenderHandlerPair` for the main → renderer channels.
 *
 * `rendererSource` is the source main sees on the sending side's messages. It defaults to the real
 * renderer; pass another source to stand in for a different peer of main, such as the browser
 * extension or CLI over native messaging.
 */
export async function setupClientPair(
  driver: AutotypeDriver = makeMockAutotypeDriver(),
  rendererSource: Source = "DesktopRenderer",
) {
  init_sdk();

  const [mainBackend, rendererBackend] = makeMockTransportPair("DesktopMain", rendererSource);
  const main = IpcClient.newWithSdkInMemorySessions(mainBackend);
  const renderer = IpcClient.newWithSdkInMemorySessions(rendererBackend);

  await main.start();
  await renderer.start();

  await registerAutotypeHandlers(main, driver);

  return { main, renderer };
}

/**
 * The mirror of `setupClientPair` for the main → renderer channels: only `renderer` registers
 * handlers, so main sends and the renderer applies.
 *
 * `mainSource` is the source the renderer sees on the sending side's messages. It defaults to the
 * real main process; pass another source to stand in for a native-messaging peer whose messages
 * main forwards to the renderer under their original source, such as the browser extension or CLI.
 */
export async function setupRenderHandlerPair(
  driver: AutotypeRenderDriver = makeMockAutotypeRenderDriver(),
  mainSource: Source = "DesktopMain",
) {
  init_sdk();

  const [mainBackend, rendererBackend] = makeMockTransportPair(mainSource, "DesktopRenderer");
  const main = IpcClient.newWithSdkInMemorySessions(mainBackend);
  const renderer = IpcClient.newWithSdkInMemorySessions(rendererBackend);

  await main.start();
  await renderer.start();

  await registerAutotypeRenderHandlers(renderer, driver);

  return { main, renderer };
}
