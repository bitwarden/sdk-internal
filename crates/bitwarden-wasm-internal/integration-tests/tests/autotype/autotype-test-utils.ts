import {
  AppMetadata,
  AutotypeCredentials,
  AutotypeMainDriver,
  AutotypeRenderDriver,
  AutotypeRunningApp,
  IpcClient,
  Source,
  init_sdk,
  registerAutotypeMainHandlers,
  registerAutotypeRenderHandlers,
} from "@bitwarden/sdk-internal";

import { makeMockTransportPair } from "../utils";

/**
 * Per-channel behavior for the mock driver. Each channel is varied independently so a test can
 * make one of them fail without disturbing the other.
 */
export interface MockAutotypeMainDriverOptions {
  setEnabled: (enabled: boolean) => Promise<boolean>;
  setKeyboardShortcut: (shortcut: string[]) => Promise<boolean>;
  // Typed loosely so a test can return a malformed payload, which is exactly what the SDK's
  // deserialization is being asked to survive.
  listRunningApps: () => Promise<unknown>;
  setConfirmationEnabled: (enabled: boolean) => Promise<boolean>;
}

/**
 * Recorded calls per channel. `list_running_apps` takes no arguments, so a count is all there is
 * to record for it.
 */
export interface MockAutotypeMainDriverCalls {
  enabledCalls: boolean[];
  shortcutCalls: string[][];
  listRunningAppsCalls: number;
  confirmationEnabledCalls: boolean[];
}

/**
 * In-memory implementation of the `AutotypeMainDriver` JS interface. Records what it was asked to do
 * per channel, and reports whether it applied the change — which the tests vary independently of
 * the request, to cover a driver that fails.
 */
export function makeMockAutotypeMainDriver(
  options: Partial<MockAutotypeMainDriverOptions> = {},
): AutotypeMainDriver & MockAutotypeMainDriverCalls {
  const {
    setEnabled = async () => true,
    setKeyboardShortcut = async () => true,
    listRunningApps = async () => [],
    setConfirmationEnabled = async () => true,
  } = options;

  const enabledCalls: boolean[] = [];
  const shortcutCalls: string[][] = [];
  const confirmationEnabledCalls: boolean[] = [];
  // A counter rather than an array, so it needs a getter — a plain number property would be
  // snapshotted at construction and never update.
  let listRunningAppsCalls = 0;

  return {
    enabledCalls,
    shortcutCalls,
    confirmationEnabledCalls,
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
    set_autotype_confirmation_enabled: async (enabled: boolean) => {
      confirmationEnabledCalls.push(enabled);
      return setConfirmationEnabled(enabled);
    },
  };
}

/**
 * Behavior for the mock render driver, the render process's side of the main → render
 * channels.
 */
export interface MockAutotypeRenderDriverOptions {
  setConfirmationEnabled: (enabled: boolean) => Promise<boolean>;
  // Typed loosely so a test can return malformed credentials, which is exactly what the SDK's
  // deserialization is being asked to survive.
  getCredentials: (app: AutotypeRunningApp, metadata: AppMetadata) => Promise<unknown>;
}

/** Recorded calls per main → render channel. */
export interface MockAutotypeRenderDriverCalls {
  confirmationEnabledCalls: boolean[];
  getCredentialsCalls: { app: AutotypeRunningApp; metadata: AppMetadata }[];
}

/**
 * In-memory implementation of the `AutotypeRenderDriver` JS interface. Records what it was asked
 * to do, and returns what the per-channel behavior gives it. By default it applies every change
 * and finds no match.
 */
export function makeMockAutotypeRenderDriver(
  options: Partial<MockAutotypeRenderDriverOptions> = {},
): AutotypeRenderDriver & MockAutotypeRenderDriverCalls {
  const { setConfirmationEnabled = async () => true, getCredentials = async () => undefined } =
    options;

  const confirmationEnabledCalls: boolean[] = [];
  const getCredentialsCalls: { app: AutotypeRunningApp; metadata: AppMetadata }[] = [];

  return {
    confirmationEnabledCalls,
    getCredentialsCalls,
    set_autotype_confirmation_enabled: async (enabled: boolean) => {
      confirmationEnabledCalls.push(enabled);
      return setConfirmationEnabled(enabled);
    },
    get_autotype_credentials: async (app: AutotypeRunningApp, metadata: AppMetadata) => {
      getCredentialsCalls.push({ app, metadata });
      return (await getCredentials(app, metadata)) as AutotypeCredentials | undefined;
    },
  };
}

/**
 * Builds the desktop pairing the real app uses: a main-process client that owns the global
 * shortcut and a render-process client that drives it, over paired in-memory transports.
 *
 * Only `main` registers handlers, matching the render → main channels — the render process sends,
 * main applies. See `setupRenderHandlerPair` for the main → render channels.
 *
 * `renderSource` is the source main sees on the sending side's messages. It defaults to the real
 * render process; pass another source to stand in for a different peer of main, such as the
 * browser extension or CLI over native messaging.
 */
export async function setupClientPair(
  driver: AutotypeMainDriver = makeMockAutotypeMainDriver(),
  renderSource: Source = "DesktopRenderer",
) {
  init_sdk();

  const [mainBackend, renderBackend] = makeMockTransportPair("DesktopMain", renderSource);
  const main = IpcClient.newWithSdkInMemorySessions(mainBackend);
  const render = IpcClient.newWithSdkInMemorySessions(renderBackend);

  await main.start();
  await render.start();

  await registerAutotypeMainHandlers(main, driver);

  return { main, render };
}

/**
 * The mirror of `setupClientPair` for the main → render channels: only `render` registers
 * handlers, so main sends and the render process applies.
 *
 * `mainSource` is the source the render process sees on the sending side's messages. It defaults
 * to the real main process; pass another source to stand in for a native-messaging peer whose
 * messages main forwards to the render process under their original source, such as the browser
 * extension or CLI.
 */
export async function setupRenderHandlerPair(
  driver: AutotypeRenderDriver = makeMockAutotypeRenderDriver(),
  mainSource: Source = "DesktopMain",
) {
  init_sdk();

  const [mainBackend, renderBackend] = makeMockTransportPair(mainSource, "DesktopRenderer");
  const main = IpcClient.newWithSdkInMemorySessions(mainBackend);
  const render = IpcClient.newWithSdkInMemorySessions(renderBackend);

  await main.start();
  await render.start();

  await registerAutotypeRenderHandlers(render, driver);

  return { main, render };
}
