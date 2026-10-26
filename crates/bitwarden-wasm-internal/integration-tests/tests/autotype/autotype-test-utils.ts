import {
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
  setConfirmationEnabledFromRenderer: (enabled: boolean) => Promise<boolean>;
}

/**
 * Recorded calls per channel. `list_running_apps` takes no arguments, so a count is all there is
 * to record for it.
 */
export interface MockAutotypeMainDriverCalls {
  enabledCalls: boolean[];
  shortcutCalls: string[][];
  listRunningAppsCalls: number;
  confirmationEnabledFromRendererCalls: boolean[];
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
    setConfirmationEnabledFromRenderer = async () => true,
  } = options;

  const enabledCalls: boolean[] = [];
  const shortcutCalls: string[][] = [];
  const confirmationEnabledFromRendererCalls: boolean[] = [];
  // A counter rather than an array, so it needs a getter — a plain number property would be
  // snapshotted at construction and never update.
  let listRunningAppsCalls = 0;

  return {
    enabledCalls,
    shortcutCalls,
    confirmationEnabledFromRendererCalls,
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
    set_autotype_confirmation_enabled_from_renderer: async (enabled: boolean) => {
      confirmationEnabledFromRendererCalls.push(enabled);
      return setConfirmationEnabledFromRenderer(enabled);
    },
  };
}

/**
 * Behavior for the mock renderer driver, the render process's side of the main → renderer
 * channels.
 */
export interface MockAutotypeRenderDriverOptions {
  setConfirmationEnabledFromMain: (enabled: boolean) => Promise<boolean>;
}

/** Recorded calls per main → renderer channel. */
export interface MockAutotypeRenderDriverCalls {
  confirmationEnabledFromMainCalls: boolean[];
}

/**
 * In-memory implementation of the `AutotypeRenderDriver` JS interface. Records what it was asked
 * to do, and reports whether it applied the change.
 */
export function makeMockAutotypeRenderDriver(
  options: Partial<MockAutotypeRenderDriverOptions> = {},
): AutotypeRenderDriver & MockAutotypeRenderDriverCalls {
  const { setConfirmationEnabledFromMain = async () => true } = options;

  const confirmationEnabledFromMainCalls: boolean[] = [];

  return {
    confirmationEnabledFromMainCalls,
    set_autotype_confirmation_enabled_from_main: async (enabled: boolean) => {
      confirmationEnabledFromMainCalls.push(enabled);
      return setConfirmationEnabledFromMain(enabled);
    },
  };
}

/**
 * Builds the desktop pairing the real app uses: a main-process client that owns the global
 * shortcut and a renderer-process client that drives it, over paired in-memory transports.
 *
 * Only `main` registers handlers, matching the renderer → main channels — the renderer sends, main
 * applies. See `setupRendererHandlerPair` for the main → renderer channels.
 *
 * `rendererSource` is the source main sees on the sending side's messages. It defaults to the real
 * renderer; pass another source to stand in for a different peer of main, such as the browser
 * extension or CLI over native messaging.
 */
export async function setupClientPair(
  driver: AutotypeMainDriver = makeMockAutotypeMainDriver(),
  rendererSource: Source = "DesktopRenderer",
) {
  init_sdk();

  const [mainBackend, rendererBackend] = makeMockTransportPair("DesktopMain", rendererSource);
  const main = IpcClient.newWithSdkInMemorySessions(mainBackend);
  const renderer = IpcClient.newWithSdkInMemorySessions(rendererBackend);

  await main.start();
  await renderer.start();

  await registerAutotypeMainHandlers(main, driver);

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
export async function setupRendererHandlerPair(
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
