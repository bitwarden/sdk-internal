// Pointing the harness at a real server.

import type { ClientSettings, LoginRequest } from "@bitwarden/sdk-internal";

/** The server URL. Its presence is what puts the harness in live mode. */
const SERVER_URL = "BW_LIVE_SERVER_URL";
/**
 * Per-service origins, for a deployment that splits them.
 *
 * A self-hosted install serves both services under one origin, at `/api` and `/identity`, which is
 * what {@link SERVER_URL} is expanded to. A cloud-style deployment gives each service an origin of
 * its own, and `GET <server>/api/config` reports them under `environment`.
 */
const API_URL = "BW_LIVE_API_URL";
const IDENTITY_URL = "BW_LIVE_IDENTITY_URL";
const EMAIL = "BW_LIVE_EMAIL";
const PASSWORD = "BW_LIVE_PASSWORD";
const DEVICE_IDENTIFIER = "BW_LIVE_DEVICE_IDENTIFIER";
const DEFAULT_DEVICE_IDENTIFIER = "sdk-internal-integration-tests";
const CLIENT_VERSION = "BW_LIVE_CLIENT_VERSION";
const DEFAULT_CLIENT_VERSION = "2026.11.0";

/**
 * The mailbox API of the mail server that receives the test accounts' email, without a trailing
 * slash. `GET <url>/<address>` lists a mailbox and `GET <url>/<address>/<id>` reads one message.
 * The mail domain of a fresh account is this URL's host.
 */
export const MAIL_API_URL = "https://kmshared.centralus.cloudapp.azure.com/mail/api/v1/mailbox";

/** The server a live test runs against, and the device it logs in from. */
export interface LiveServer {
  settings: ClientSettings;
  loginRequest: LoginRequest;
}

/** An account on the live server, and the master password that logs it in. */
export interface LiveAccount {
  email: string;
  password: string;
}

/** The live server, plus the fixed account from {@link EMAIL} and {@link PASSWORD}. */
export interface LiveConfig extends LiveServer, LiveAccount {}

/**
 * The live server, or `undefined` when {@link SERVER_URL} is unset.
 *
 * Enough for a test that registers its own account. A test on the fixed account uses
 * {@link liveConfig}.
 */
export function liveServer(): LiveServer | undefined {
  return isSet(SERVER_URL) ? requireLiveServer() : undefined;
}

/**
 * The live server and the fixed account, or `undefined` when either is unconfigured.
 *
 * A run can configure only the server, for the tests that register their own account. Setting one
 * of {@link EMAIL} and {@link PASSWORD} without the other is a mistake and throws.
 */
export function liveConfig(): LiveConfig | undefined {
  if (!isSet(SERVER_URL) || (!isSet(EMAIL) && !isSet(PASSWORD))) {
    return undefined;
  }

  return requireLiveConfig();
}

export function requireLiveConfig(): LiveConfig {
  return {
    ...requireLiveServer(),
    email: required(EMAIL),
    password: required(PASSWORD),
  };
}

export function requireLiveServer(): LiveServer {
  const baseUrl = trimTrailingSlash(required(SERVER_URL));
  const deviceIdentifier = process.env[DEVICE_IDENTIFIER] ?? DEFAULT_DEVICE_IDENTIFIER;

  return {
    settings: {
      apiUrl: originOr(API_URL, `${baseUrl}/api`),
      identityUrl: originOr(IDENTITY_URL, `${baseUrl}/identity`),
      deviceIdentifier,
      bitwardenClientVersion: process.env[CLIENT_VERSION] ?? DEFAULT_CLIENT_VERSION,
    },
    loginRequest: {
      clientId: "web",
      device: {
        deviceType: "SDK",
        deviceIdentifier,
        deviceName: "SDK Integration Tests",
        devicePushToken: undefined,
      },
    },
  };
}

export function describeLoginFailure(error: unknown): string {
  return [
    `live login failed: ${String(error)}`,
    `check ${EMAIL} and ${PASSWORD};`,
    "the account must have two-factor disabled, no captcha requirement, and new-device",
    `verification already satisfied for device ${
      process.env[DEVICE_IDENTIFIER] ?? DEFAULT_DEVICE_IDENTIFIER
    }.`,
    "The SDK reports all three as the same unknown error, so none can be told apart here.",
  ].join(" ");
}

function originOr(name: string, fallback: string): string {
  const configured = process.env[name];

  return configured === undefined || configured === "" ? fallback : trimTrailingSlash(configured);
}

function isSet(name: string): boolean {
  const value = process.env[name];

  return value !== undefined && value !== "";
}

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value === "") {
    throw new Error(
      `${name} is not set; live mode needs ${SERVER_URL}, and tests on the fixed account also ` +
        `need ${EMAIL} and ${PASSWORD}`,
    );
  }

  return value;
}

function trimTrailingSlash(url: string): string {
  return url.endsWith("/") ? url.slice(0, -1) : url;
}
